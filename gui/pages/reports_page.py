"""
gui/pages/reports_page.py

Phase 14 / Section 25: Forensic Report Generation & Export Page.

Provides one-click generation of PDF forensic reports and security audit summaries.
"""

import os
import subprocess
import sys
import time
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database.db_manager import DatabaseManager
from reporting.report_generator import ReportGenerator, REPORTS_DIR


class ReportsPage(QWidget):
    """Forensic report generation and archive viewer."""

    def __init__(self, db: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.report_gen = ReportGenerator()
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        title = QLabel("📄 Forensic PDF Reporting & Audit Center")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        layout.addWidget(title)

        # Action Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)

        # Card 1: System Security Audit
        card_audit = QFrame()
        card_audit.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        c1_layout = QVBoxLayout(card_audit)
        lbl_c1_title = QLabel("📊 Complete Security Audit Report")
        lbl_c1_title.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_c1_title.setStyleSheet("color: #38bdf8;")
        c1_layout.addWidget(lbl_c1_title)

        lbl_c1_desc = QLabel("Generates a comprehensive forensic PDF summarizing endpoint status, all logged threat detections, and termination audit trails.")
        lbl_c1_desc.setFont(QFont("Arial", 9))
        lbl_c1_desc.setWordWrap(True)
        lbl_c1_desc.setStyleSheet("color: #94a3b8;")
        c1_layout.addWidget(lbl_c1_desc)

        btn_audit = QPushButton("Generate Full Security Audit PDF")
        btn_audit.setFont(QFont("Arial", 10, QFont.Bold))
        btn_audit.setCursor(Qt.PointingHandCursor)
        btn_audit.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        btn_audit.clicked.connect(self._generate_full_audit_pdf)
        c1_layout.addWidget(btn_audit)

        cards_layout.addWidget(card_audit)

        # Card 2: Latest Incident
        card_latest = QFrame()
        card_latest.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        c2_layout = QVBoxLayout(card_latest)
        lbl_c2_title = QLabel("🚨 Latest Incident Investigation Report")
        lbl_c2_title.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_c2_title.setStyleSheet("color: #f43f5e;")
        c2_layout.addWidget(lbl_c2_title)

        lbl_c2_desc = QLabel("Generates a case-specific forensic report detailing the most recently detected ransomware burst, offending PID, and telemetry.")
        lbl_c2_desc.setFont(QFont("Arial", 9))
        lbl_c2_desc.setWordWrap(True)
        lbl_c2_desc.setStyleSheet("color: #94a3b8;")
        c2_layout.addWidget(lbl_c2_desc)

        btn_latest = QPushButton("Generate Latest Incident PDF")
        btn_latest.setFont(QFont("Arial", 10, QFont.Bold))
        btn_latest.setCursor(Qt.PointingHandCursor)
        btn_latest.setStyleSheet("""
            QPushButton {
                background-color: #e11d48;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
            }
            QPushButton:hover { background-color: #be123c; }
        """)
        btn_latest.clicked.connect(self._generate_latest_incident_pdf)
        c2_layout.addWidget(btn_latest)

        cards_layout.addWidget(card_latest)
        layout.addLayout(cards_layout)

        # Reports Directory List
        sec_header = QHBoxLayout()
        lbl_files = QLabel("📁 Generated Report Documents Archive")
        lbl_files.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_files.setStyleSheet("color: #cbd5e1;")
        sec_header.addWidget(lbl_files)
        sec_header.addStretch()

        btn_open_folder = QPushButton("Open Reports Folder")
        btn_open_folder.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 5px 10px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        btn_open_folder.clicked.connect(self._open_reports_folder)
        sec_header.addWidget(btn_open_folder)

        layout.addLayout(sec_header)

        # Table of PDF Files
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["PDF File Name", "File Size", "Created Date", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 8px;
                gridline-color: #1e293b;
                color: #e2e8f0;
            }
            QHeaderView::section {
                background-color: #1e293b;
                color: #94a3b8;
                font-weight: bold;
                padding: 8px;
                border: none;
            }
        """)
        layout.addWidget(self.table)

        self.refresh_pdf_list()

    def _generate_full_audit_pdf(self):
        try:
            incidents = self.db.get_recent_incidents(limit=100)
            stats = self.db.get_stats()
            pdf_path = self.report_gen.generate_security_audit_report(incidents, stats)
            self.refresh_pdf_list()
            QMessageBox.information(self, "Security Audit Generated", f"Successfully generated security audit report:\n\n{pdf_path}")
        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Could not generate audit report: {e}")

    def _generate_latest_incident_pdf(self):
        incidents = self.db.get_recent_incidents(limit=1)
        if not incidents:
            QMessageBox.warning(self, "No Incidents", "No threat incidents have been logged yet to generate a report.")
            return

        try:
            pdf_path = self.report_gen.generate_incident_report(incidents[0])
            self.refresh_pdf_list()
            QMessageBox.information(self, "Incident Report Generated", f"Successfully generated report for latest incident:\n\n{pdf_path}")
        except Exception as e:
            QMessageBox.critical(self, "Generation Failed", f"Could not generate report: {e}")

    def refresh_pdf_list(self):
        if not os.path.exists(REPORTS_DIR):
            return

        files = [f for f in os.listdir(REPORTS_DIR) if f.endswith(".pdf")]
        files.sort(key=lambda x: os.path.getmtime(os.path.join(REPORTS_DIR, x)), reverse=True)

        self.table.setRowCount(len(files))

        for row, fname in enumerate(files):
            fpath = os.path.join(REPORTS_DIR, fname)
            size_kb = os.path.getsize(fpath) / 1024.0
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fpath)))

            self.table.setItem(row, 0, QTableWidgetItem(fname))
            self.table.setItem(row, 1, QTableWidgetItem(f"{size_kb:.1f} KB"))
            self.table.setItem(row, 2, QTableWidgetItem(mtime))

            btn_open = QPushButton("Open PDF")
            btn_open.setCursor(Qt.PointingHandCursor)
            btn_open.setStyleSheet("""
                QPushButton {
                    background-color: #3b82f6;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 10px;
                }
                QPushButton:hover { background-color: #2563eb; }
            """)
            btn_open.clicked.connect(lambda _, p=fpath: self._open_file(p))
            self.table.setCellWidget(row, 3, btn_open)

    def _open_file(self, path: str):
        if sys.platform == "darwin":
            subprocess.run(["open", path])
        elif sys.platform == "win32":
            os.startfile(path)
        else:
            subprocess.run(["xdg-open", path])

    def _open_reports_folder(self):
        self._open_file(REPORTS_DIR)

