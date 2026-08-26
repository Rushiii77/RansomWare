"""
tests/benchmark_pipeline.py

Performance & throughput benchmark for:
1. FileMonitor ring buffer ingestion and query throughput.
2. FeatureExtractor calculation speed over large event windows (1,000 to 50,000 events).
3. ProcessMonitor snapshot querying latency.
"""

import time
import config
from features.feature_extractor import FeatureExtractor
from monitoring.file_monitor import FileMonitor, FileEvent
from monitoring.process_monitor import ProcessMonitor, ProcessSnapshot


def benchmark_feature_extraction(num_events: int = 10000, iterations: int = 100):
    print(f"\n--- Benchmarking FeatureExtractor ({num_events:,} events, {iterations} iterations) ---")
    now = time.time()
    events = [
        FileEvent(
            timestamp=now - (i % 10),
            event_type=["created", "modified", "deleted", "moved"][i % 4],
            src_path=f"/test/dir_{i % 5}/file_{i % 50}.txt",
            dest_path=f"/test/dir_{i % 5}/file_{i % 50}.sim_locked" if (i % 4 == 3) else None,
        )
        for i in range(num_events)
    ]
    proc = ProcessSnapshot(
        pid=101, name="python", exe_path="/usr/bin/python",
        cpu_percent=12.5, memory_mb=55.0, status="running",
        create_time=now, username="bench"
    )

    extractor = FeatureExtractor(window_seconds=10.0)

    start = time.perf_counter()
    for _ in range(iterations):
        _ = extractor.extract(events, process_snapshot=proc)
    elapsed = time.perf_counter() - start

    avg_ms = (elapsed / iterations) * 1000.0
    throughput = (num_events * iterations) / elapsed
    print(f"Total time: {elapsed:.4f}s | Avg latency per extract: {avg_ms:.2f} ms")
    print(f"Throughput: {throughput:,.0f} events/sec evaluated")


def benchmark_ring_buffer(history_size: int = 5000, queries: int = 500):
    print(f"\n--- Benchmarking FileMonitor Ring Buffer (buffer size={history_size:,}, {queries} queries) ---")
    fm = FileMonitor(watch_path=config.DEFAULT_WATCH_DIRECTORY, history_limit=history_size)
    now = time.time()

    for i in range(history_size):
        fm._buffer.append(
            FileEvent(
                timestamp=now - (history_size - i) * 0.01,
                event_type="modified",
                src_path=f"/path/to/file_{i}.txt"
            )
        )

    start = time.perf_counter()
    for _ in range(queries):
        _ = fm.get_recent_events(seconds=5.0)
    elapsed = time.perf_counter() - start

    avg_us = (elapsed / queries) * 1_000_000.0
    print(f"Total time: {elapsed:.4f}s | Avg query latency: {avg_us:.2f} µs")


def benchmark_process_monitor():
    print("\n--- Benchmarking ProcessMonitor Single Poll Latency ---")
    monitor = ProcessMonitor()
    start = time.perf_counter()
    monitor._poll_once()
    elapsed = (time.perf_counter() - start) * 1000.0
    procs = monitor.get_all_processes()
    print(f"Scanned {len(procs)} system processes in {elapsed:.2f} ms")


def run_benchmarks():
    print("=" * 60)
    print("           RANSOMWARE DETECTION BENCHMARK SUITE")
    print("=" * 60)
    benchmark_feature_extraction(num_events=5000, iterations=50)
    benchmark_ring_buffer(history_size=5000, queries=500)
    benchmark_process_monitor()
    print("\nBenchmark completed successfully.")


if __name__ == "__main__":
    run_benchmarks()

