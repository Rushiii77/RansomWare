"""
gui/pages/alerts_page.py

Phase 14 / Section 23: Threat Alerts & Immediate Action Page.

Displays active security alerts, severity classifications, and response controls.
"""

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ml.detector import DetectionResult, ThreatLevel
from response.process_terminator import ProcessTerminator


class AlertsPage(QWidget):
    """Threat alerts management and rapid response view."""

    action_triggered = Signal(str, int, str)  # action, pid, name

    def __init__(self, terminator: ProcessTerminator, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.terminator = terminator
        self._alerts: List[DetectionResult] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header
        top_bar = QHBoxLayout()
        title = QLabel("🚨 Threat Alerts & Incident Response")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        top_bar.addWidget(title)
        top_bar.addStretch()

        layout.addLayout(top_bar)

        # Alerts Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Time", "Threat Level", "Confidence", "Offending Process", "PID", "Top Signature", "Response Actions"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
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

    def add_alert(self, result: DetectionResult):
        """Prepend new detection alert."""
        self._alerts.insert(0, result)
        if len(self._alerts) > 50:
            self._alerts.pop()
        self._render_table()

    def _render_table(self):
        self.table.setRowCount(len(self._alerts))

        for row, alert in enumerate(self._alerts):
            # Time
            import time
            t_str = time.strftime("%H:%M:%S", time.localtime(alert.evaluated_at))
            self.table.setItem(row, 0, QTableWidgetItem(t_str))

            # Threat Level
            item_lvl = QTableWidgetItem(alert.threat_level.value)
            item_lvl.setTextAlignment(Qt.AlignCenter)
            item_lvl.setFont(QFont("Arial", 9, QFont.Bold))
            if alert.threat_level == ThreatLevel.CRITICAL:
                item_lvl.setForeground(QColor("#ef4444"))
            elif alert.threat_level == ThreatLevel.HIGH_RISK:
                item_lvl.setForeground(QColor("#f97316"))
            else:
                item_lvl.setForeground(QColor("#eab308"))
            self.table.setItem(row, 1, item_lvl)

            # Confidence
            item_conf = QTableWidgetItem(f"{alert.confidence * 100:.1f}%")
            item_conf.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, item_conf)

            # Process Name & PID
            pname = alert.suspect_name or "Unknown"
            pid = str(alert.suspect_pid or "—")
            self.table.setItem(row, 3, QTableWidgetItem(pname))
            self.table.setItem(row, 4, QTableWidgetItem(pid))

            # Signature
            f = alert.features
            renames = f.get("num_renamed", 0)
            ratio = f.get("rename_modify_ratio", 0.0)
            sig_text = f"{renames:.0f} renames (Ratio: {ratio:.2f})"
            self.table.setItem(row, 5, QTableWidgetItem(sig_text))

            # Action Buttons Frame
            action_widget = QWidget()
            btn_box = QHBoxLayout(action_widget)
            btn_box.setContentsMargins(4, 2, 4, 2)
            btn_box.setSpacing(6)

            btn_term = QPushButton("🛑 Terminate")
            btn_term.setCursor(Qt.PointingHandCursor)
            btn_term.setStyleSheet("""
                QPushButton {
                    background-color: #dc2626;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 8px;
                    font-size: 10px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #b91c1c; }
            """)
            btn_term.clicked.connect(lambda _, p=alert.suspect_pid, n=pname: self.action_triggered.emit("terminate", p or 0, n))
            btn_box.addWidget(btn_term)

            self.table.setCellWidget(row, 6, action_widget)

