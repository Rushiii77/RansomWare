"""
gui/pages/incidents_page.py

Phase 14 / Section 24: Incident History & Forensic Audit Trail Page.

Queries SQLite database (`incidents.db`), displays complete historical detection
and response records, and allows instant PDF report generation for any incident.
"""

import time
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from database.db_manager import DatabaseManager, IncidentRecord
from reporting.report_generator import ReportGenerator


class IncidentsPage(QWidget):
    """Incident history audit trail table with PDF generation."""

    def __init__(self, db: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self.report_gen = ReportGenerator()
        self._incidents: List[IncidentRecord] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header Bar
        top_bar = QHBoxLayout()

        title = QLabel("📜 Security Incident Audit Log")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        top_bar.addWidget(title)

        top_bar.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by Case ID or Process Name...")
        self.search_input.setFixedWidth(280)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 12px;
                color: #f8fafc;
            }
        """)
        self.search_input.textChanged.connect(self._filter_table)
        top_bar.addWidget(self.search_input)

        self.btn_refresh = QPushButton("🔄 Refresh")
        self.btn_refresh.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        self.btn_refresh.clicked.connect(self.load_incidents)
        top_bar.addWidget(self.btn_refresh)

        layout.addLayout(top_bar)

        # Incident Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Case ID", "Timestamp", "Threat Level", "Risk Score", "Offending Process", "PID", "Action Taken", "Forensic PDF"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

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

        self.load_incidents()

    def load_incidents(self):
        """Fetch incidents from SQLite."""
        self._incidents = self.db.get_recent_incidents(limit=100)
        self._filter_table(self.search_input.text())

    def _filter_table(self, query: str):
        query = query.strip().lower()
        filtered = [
            inc for inc in self._incidents
            if not query or (
                query in f"inc-{inc.id:04d}".lower()
                or (inc.suspect_name and query in inc.suspect_name.lower())
                or query in str(inc.suspect_pid or "")
            )
        ]

        self.table.setRowCount(len(filtered))

        for row, inc in enumerate(filtered):
            # Case ID
            item_id = QTableWidgetItem(f"INC-{inc.id:04d}")
            item_id.setTextAlignment(Qt.AlignCenter)
            item_id.setFont(QFont("Arial", 9, QFont.Bold))
            self.table.setItem(row, 0, item_id)

            # Timestamp
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(inc.timestamp))
            self.table.setItem(row, 1, QTableWidgetItem(t_str))

            # Threat Level
            item_lvl = QTableWidgetItem(inc.threat_level)
            item_lvl.setTextAlignment(Qt.AlignCenter)
            item_lvl.setFont(QFont("Arial", 9, QFont.Bold))
            if inc.threat_level in ("CRITICAL", "HIGH_RISK"):
                item_lvl.setForeground(QColor("#ef4444"))
            else:
                item_lvl.setForeground(QColor("#eab308"))
            self.table.setItem(row, 2, item_lvl)

            # Risk Score
            score = int(inc.confidence * 100)
            item_score = QTableWidgetItem(f"{score}/100")
            item_score.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, item_score)

            # Process Name & PID
            self.table.setItem(row, 4, QTableWidgetItem(inc.suspect_name or "Unknown"))
            self.table.setItem(row, 5, QTableWidgetItem(str(inc.suspect_pid or "—")))

            # Action Taken
            self.table.setItem(row, 6, QTableWidgetItem(inc.action_taken))

            # PDF Action Button
            btn_pdf = QPushButton("📄 Generate PDF")
            btn_pdf.setCursor(Qt.PointingHandCursor)
            btn_pdf.setStyleSheet("""
                QPushButton {
                    background-color: #2563eb;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 10px;
                    font-size: 11px;
                }
                QPushButton:hover { background-color: #1d4ed8; }
            """)
            btn_pdf.clicked.connect(lambda _, item=inc: self._generate_pdf_for_incident(item))
            self.table.setCellWidget(row, 7, btn_pdf)

    def _generate_pdf_for_incident(self, incident: IncidentRecord):
        try:
            pdf_path = self.report_gen.generate_incident_report(incident)
            QMessageBox.information(
                self,
                "Forensic Report Generated",
                f"Successfully generated PDF report for Case #INC-{incident.id:04d}:\n\n{pdf_path}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Could not generate PDF: {e}")

