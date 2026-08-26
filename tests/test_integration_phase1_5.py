"""
tests/test_integration_phase1_5.py

Integrated manual test for the current 30% delivery (Phases 1-5).

This ties together:
    - ProcessMonitor  (Phase 2)
    - FileMonitor     (Phase 3)
    - FeatureExtractor (Phase 4)
    - SafeRansomwareSimulator (Phase 5)

It is NOT an automated pytest suite (no ML/response/GUI exists yet to
assert against) — it is a guided manual demo you run and visually
verify, matching the "test procedure / expected output" requirement
for each phase.

Run from the project root:
    python -m tests.test_integration_phase1_5
"""

import time

import config
from monitoring.process_monitor import ProcessMonitor
from monitoring.file_monitor import FileMonitor
from features.feature_extractor import FeatureExtractor
from simulator.safe_ransomware_simulator import SafeRansomwareSimulator
from utils.logger import get_logger

logger = get_logger("test_integration")


def main():
    print("=" * 70)
    print("PHASE 1-5 INTEGRATION TEST")
    print("=" * 70)
    print(f"Safe test directory: {config.TEST_ENV_DIR}")
    print()

    process_monitor = ProcessMonitor(poll_interval=2.0)
    file_monitor = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
    extractor = FeatureExtractor(window_seconds=10)

    process_monitor.start()
    file_monitor.start()

    print("Baseline (no activity yet) — waiting 3s...")
    time.sleep(3)
    baseline = extractor.extract(file_monitor.get_recent_events(seconds=10))
    print("Baseline features:", baseline.features)
    print()

    print("Launching safe ransomware-behavior simulator...")
    simulator = SafeRansomwareSimulator(num_files=50)
    simulator.run_full_simulation()

    print()
    print("Sampling features every 2s for 12s after simulation burst:")
    print("(expect operation counts / rate to spike, then decay as the")
    print(" window rolls forward)")
    print("-" * 70)

    for _ in range(6):
        time.sleep(2)
        events = file_monitor.get_recent_events(seconds=extractor.window_seconds)
        result = extractor.extract(events)
        print(f"[{time.strftime('%H:%M:%S')}] "
              f"events_in_window={result.event_count:<4} "
              f"created={result.features['num_created']:.0f} "
              f"modified={result.features['num_modified']:.0f} "
              f"renamed={result.features['num_renamed']:.0f} "
              f"rate/s={result.features['operation_rate_per_sec']:.2f}")

    print("-" * 70)
    print(f"Process monitor currently tracking {process_monitor.process_count()} processes.")
    print()

    print("Cleaning up simulator files...")
    simulator.cleanup()

    file_monitor.stop()
    process_monitor.stop()
    print("Test complete.")


if __name__ == "__main__":
    main()
