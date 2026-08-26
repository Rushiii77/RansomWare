"""
tests/test_unit_response.py

Automated unit tests for:
- ProcessTerminator (safe termination, system process protection)
- DatabaseManager (incident recording, whitelisting, stats)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from database.db_manager import DatabaseManager, IncidentRecord
from response.process_terminator import ProcessTerminator, TerminationStatus, PROTECTED_SYSTEM_BINARIES


class TestProcessTerminator(unittest.TestCase):
    def setUp(self):
        self.terminator = ProcessTerminator()

    def test_protected_system_processes(self):
        # Root PID 0 and 1
        self.assertTrue(self.terminator.is_protected(0, "kernel"))
        self.assertTrue(self.terminator.is_protected(1, "launchd"))

        # Protected binaries
        self.assertTrue(self.terminator.is_protected(999, "launchd"))
        self.assertTrue(self.terminator.is_protected(999, "Finder"))
        self.assertTrue(self.terminator.is_protected(999, "explorer.exe"))
        self.assertTrue(self.terminator.is_protected(999, "kernel_task"))

        # Refuse to terminate system root
        rep = self.terminator.terminate_process(1, reason="Test")
        self.assertEqual(rep.status, TerminationStatus.PROTECTED_SYSTEM_PROCESS)

        # Refuse to terminate protected binary name
        rep2 = self.terminator.terminate_process(0, reason="Test")
        self.assertEqual(rep2.status, TerminationStatus.PROTECTED_SYSTEM_PROCESS)

    def test_terminate_real_child_process(self):
        # Spawn a harmless dummy python process
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid

        try:
            self.assertFalse(self.terminator.is_protected(pid, "dummy_worker"))
            report = self.terminator.terminate_process(pid, reason="Unit test termination")
            self.assertIn(report.status, (TerminationStatus.TERMINATED, TerminationStatus.KILLED_FORCEFULLY))
            self.assertEqual(report.pid, pid)

            # Confirm process is dead
            proc.poll()
            self.assertIsNotNone(proc.returncode)
        finally:
            if proc.poll() is None:
                proc.kill()


class TestDatabaseManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_incidents.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_record_and_get_incidents(self):
        inc_id = self.db.record_incident(
            threat_level="CRITICAL",
            confidence=0.98,
            suspect_pid=1234,
            suspect_name="malicious_sim.py",
            action_taken="TERMINATED",
            features={"num_renamed": 150.0, "rename_modify_ratio": 1.0},
            details="SIGTERM sent",
        )
        self.assertGreater(inc_id, 0)

        incidents = self.db.get_recent_incidents(limit=10)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.threat_level, "CRITICAL")
        self.assertEqual(inc.suspect_pid, 1234)
        self.assertEqual(inc.suspect_name, "malicious_sim.py")
        self.assertEqual(inc.action_taken, "TERMINATED")
        self.assertEqual(inc.features["num_renamed"], 150.0)

    def test_whitelist_operations(self):
        self.assertFalse(self.db.is_whitelisted("my_safe_app"))
        self.assertTrue(self.db.add_to_whitelist("my_safe_app", path="/usr/local/bin/my_safe_app"))
        self.assertTrue(self.db.is_whitelisted("my_safe_app"))
        self.assertTrue(self.db.is_whitelisted("MY_SAFE_APP"))  # Case insensitive

        wl = self.db.get_whitelist()
        self.assertIn("my_safe_app", wl)

    def test_stats(self):
        self.db.record_incident("HIGH_RISK", 0.85, 111, "app1", "TERMINATED")
        self.db.record_incident("SUSPICIOUS", 0.60, 222, "app2", "IGNORED_BY_USER")

        stats = self.db.get_stats()
        self.assertEqual(stats["total_threats"], 2)
        self.assertEqual(stats["terminated"], 1)
        self.assertEqual(stats["ignored"], 1)


if __name__ == "__main__":
    unittest.main()

