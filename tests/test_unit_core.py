"""
tests/test_unit_core.py

Automated unit tests for core modules (Phases 1-5):
- config & logger
- ProcessMonitor
- FileMonitor & FileEvent metadata
- FeatureExtractor & Vector extraction
- SafeRansomwareSimulator & SafetyViolation checks
"""

import os
import shutil
import tempfile
import time
import unittest

import config
from features.feature_extractor import FeatureExtractor, FEATURE_NAMES, FeatureWindowResult
from monitoring.file_monitor import FileMonitor, FileEvent
from monitoring.process_monitor import ProcessMonitor, ProcessSnapshot
from simulator.safe_ransomware_simulator import SafeRansomwareSimulator, SafetyViolationError
from utils.logger import get_logger


class TestConfigAndLogger(unittest.TestCase):
    def test_paths_exist(self):
        self.assertTrue(os.path.isdir(config.LOG_DIR))
        self.assertTrue(os.path.isdir(config.DATASET_DIR))
        self.assertTrue(os.path.isdir(config.TEST_ENV_DIR))

    def test_logger_creation(self):
        logger = get_logger("unit_test")
        self.assertIsNotNone(logger)
        logger.info("Unit test logger message.")


class TestProcessMonitor(unittest.TestCase):
    def test_poll_and_read(self):
        monitor = ProcessMonitor(poll_interval=1.0)
        # Test direct single poll
        monitor._poll_once()
        procs = monitor.get_all_processes()
        self.assertGreater(len(procs), 0)

        first_proc = procs[0]
        self.assertIsInstance(first_proc, ProcessSnapshot)
        self.assertIsInstance(first_proc.pid, int)
        self.assertIsInstance(first_proc.name, str)

        fetched = monitor.get_process(first_proc.pid)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.pid, first_proc.pid)


class TestFileEventAndMonitor(unittest.TestCase):
    def test_file_event_precomputed_metadata(self):
        event = FileEvent(
            timestamp=time.time(),
            event_type="created",
            src_path="/tmp/test_dir/sample_file.txt",
        )
        self.assertEqual(event.ext, ".txt")
        self.assertEqual(event.dir_path, "/tmp/test_dir")

    def test_recent_events_cutoff_order(self):
        fm = FileMonitor(watch_path=config.DEFAULT_WATCH_DIRECTORY, history_limit=100)
        now = time.time()

        # Inject simulated events in order
        for i in range(10):
            fm._buffer.append(FileEvent(
                timestamp=now - (10 - i),
                event_type="created",
                src_path=f"/test/path_{i}.txt",
            ))

        # Request last 4 seconds
        recent = fm.get_recent_events(seconds=4.5)
        self.assertLessEqual(len(recent), 5)
        # Verify chronological order
        timestamps = [e.timestamp for e in recent]
        self.assertEqual(timestamps, sorted(timestamps))


class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_seconds=10.0)

    def test_feature_calculation(self):
        now = time.time()
        events = [
            FileEvent(timestamp=now, event_type="created", src_path="/dir1/file1.txt"),
            FileEvent(timestamp=now, event_type="created", src_path="/dir1/file2.docx"),
            FileEvent(timestamp=now, event_type="modified", src_path="/dir1/file1.txt"),
            FileEvent(timestamp=now, event_type="moved", src_path="/dir1/file1.txt", dest_path="/dir1/file1.txt.sim_locked"),
            FileEvent(timestamp=now, event_type="deleted", src_path="/dir2/file3.jpg"),
        ]
        proc = ProcessSnapshot(
            pid=1234,
            name="test_proc",
            exe_path="/usr/bin/test",
            cpu_percent=15.5,
            memory_mb=42.0,
            status="running",
            create_time=now,
            username="user",
        )

        result = self.extractor.extract(events, process_snapshot=proc)
        self.assertIsInstance(result, FeatureWindowResult)
        f = result.features

        self.assertEqual(f["num_created"], 2.0)
        self.assertEqual(f["num_modified"], 1.0)
        self.assertEqual(f["num_renamed"], 1.0)
        self.assertEqual(f["num_deleted"], 1.0)
        self.assertEqual(f["total_operations"], 5.0)
        self.assertEqual(f["operation_rate_per_sec"], 0.5)
        self.assertEqual(f["unique_directories"], 2.0)
        self.assertEqual(f["unique_extensions"], 4.0)  # .txt, .docx, .sim_locked, .jpg
        self.assertEqual(f["cpu_percent"], 15.5)
        self.assertEqual(f["memory_mb"], 42.0)

    def test_vector_conversion(self):
        events = [
            FileEvent(timestamp=time.time(), event_type="created", src_path="/dir/f.txt")
        ]
        vec = self.extractor.extract_vector(events)
        self.assertEqual(len(vec), len(FEATURE_NAMES))
        self.assertIsInstance(vec, list)


class TestSafeRansomwareSimulator(unittest.TestCase):
    def test_sandbox_safety_enforcement(self):
        # Simulator should refuse to target system paths
        with self.assertRaises(SafetyViolationError):
            SafeRansomwareSimulator(target_dir="/etc")

        with self.assertRaises(SafetyViolationError):
            SafeRansomwareSimulator(target_dir=os.path.expanduser("~"))

    def test_safe_lifecycle(self):
        sim = SafeRansomwareSimulator(num_files=5)
        created = sim.setup_files()
        self.assertEqual(len(created), 5)
        for p in created:
            self.assertTrue(os.path.isfile(p))

        sim.run_modify_burst(iterations=1, delay=0.001)
        sim.run_rename_burst()
        self.assertTrue(all(f.endswith(config.SIMULATOR_RENAMED_SUFFIX) for f in sim._created_files))

        sim.cleanup()
        self.assertEqual(len(sim._created_files), 0)


if __name__ == "__main__":
    unittest.main()

