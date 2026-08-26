"""
tests/test_unit_reporting.py

Automated unit tests for Phase 15:
- PDF Incident Forensic Report Generation
- Security Audit Summary PDF Report Generation
"""

import os
import shutil
import tempfile
import time
import unittest

from database.db_manager import IncidentRecord
from reporting.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_incident_report_pdf(self):
        incident = IncidentRecord(
            id=1,
            timestamp=time.time(),
            threat_level="CRITICAL",
            confidence=0.985,
            suspect_pid=4820,
            suspect_name="test_simulator.exe",
            action_taken="TERMINATED (SIGTERM)",
            features={
                "total_operations": 250.0,
                "operation_rate_per_sec": 25.0,
                "num_renamed": 120.0,
                "num_modified": 125.0,
                "rename_modify_ratio": 0.96,
                "unique_directories": 6.0,
                "unique_extensions": 4.0,
                "cpu_percent": 65.0,
            },
            details="Process terminated gracefully via SIGTERM.",
        )

        pdf_path = self.generator.generate_incident_report(incident)
        self.assertTrue(os.path.isfile(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 1000)  # Valid PDF size

    def test_generate_security_audit_report_pdf(self):
        incidents = [
            IncidentRecord(
                id=1,
                timestamp=time.time() - 100,
                threat_level="CRITICAL",
                confidence=0.95,
                suspect_pid=111,
                suspect_name="bad_app.exe",
                action_taken="TERMINATED",
                features={"total_operations": 100.0},
                details="Terminated",
            ),
            IncidentRecord(
                id=2,
                timestamp=time.time(),
                threat_level="SUSPICIOUS",
                confidence=0.60,
                suspect_pid=222,
                suspect_name="unknown.exe",
                action_taken="IGNORED_BY_USER",
                features={"total_operations": 20.0},
                details="Ignored",
            ),
        ]
        stats = {"total_threats": 2, "terminated": 1, "ignored": 1}

        pdf_path = self.generator.generate_security_audit_report(incidents, stats)
        self.assertTrue(os.path.isfile(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 1000)


if __name__ == "__main__":
    unittest.main()

