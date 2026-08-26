"""
gui/pages/processes_page.py

Phase 14 / Section 21: Live Running Processes Management Page.

Searchable, sortable table displaying running processes, telemetry metrics,
estimated risk levels, and manual termination controls.
"""

from typing import List, Optional

from PySide6.QtCore import Qt, Signal
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

from monitoring.process_monitor import ProcessSnapshot
from response.process_terminator import ProcessTerminator, TerminationStatus


class ProcessesPage(QWidget):
    """Running processes view with manual termination controls."""

    process_terminated = Signal(int, str)  # pid, name

    def __init__(self, terminator: ProcessTerminator, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.terminator = terminator
        self._all_processes: List[ProcessSnapshot] = []
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header & Search Bar
        top_bar = QHBoxLayout()

        title = QLabel("🔍 Active Running Processes")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        top_bar.addWidget(title)

        top_bar.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter by PID or Process Name...")
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

        layout.addLayout(top_bar)

        # Process Table
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "PID", "Process Name", "CPU %", "Memory (MB)", "Status", "Risk Level", "Score", "Action"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)

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
            QTableWidget::item:selected {
                background-color: #334155;
            }
        """)
        layout.addWidget(self.table)

    def update_processes(self, procs: List[ProcessSnapshot]):
        """Update live processes from monitor."""
        self._all_processes = procs
        self._filter_table(self.search_input.text())

    def _filter_table(self, query: str):
        query = query.strip().lower()
        filtered = [
            p for p in self._all_processes
            if not query or (query in p.name.lower() or query in str(p.pid))
        ]

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(filtered))

        for row, p in enumerate(filtered):
            # PID
            item_pid = QTableWidgetItem(str(p.pid))
            item_pid.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, item_pid)

            # Name
            self.table.setItem(row, 1, QTableWidgetItem(p.name))

            # CPU
            item_cpu = QTableWidgetItem(f"{p.cpu_percent:.1f}%")
            item_cpu.setTextAlignment(Qt.AlignCenter)
            if p.cpu_percent > 40.0:
                item_cpu.setForeground(QColor("#f97316"))
            self.table.setItem(row, 2, item_cpu)

            # Memory
            item_mem = QTableWidgetItem(f"{p.memory_mb:.1f} MB")
            item_mem.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 3, item_mem)

            # Status
            item_status = QTableWidgetItem(p.status)
            item_status.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 4, item_status)

            # Estimated Risk
            is_suspicious = p.cpu_percent > 60.0
            risk_label = "SUSPICIOUS" if is_suspicious else "BENIGN"
            score = 65 if is_suspicious else 10

            item_risk = QTableWidgetItem(risk_label)
            item_risk.setTextAlignment(Qt.AlignCenter)
            item_risk.setForeground(QColor("#eab308" if is_suspicious else "#22c55e"))
            self.table.setItem(row, 5, item_risk)

            item_score = QTableWidgetItem(f"{score}/100")
            item_score.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 6, item_score)

            # Terminate Action Button
            btn_term = QPushButton("Terminate")
            btn_term.setCursor(Qt.PointingHandCursor)
            btn_term.setStyleSheet("""
                QPushButton {
                    background-color: #ef4444;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 10px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #dc2626; }
            """)
            btn_term.clicked.connect(lambda _, pid=p.pid, name=p.name: self._handle_terminate(pid, name))
            self.table.setCellWidget(row, 7, btn_term)

        self.table.setSortingEnabled(True)

    def _handle_terminate(self, pid: int, name: str):
        reply = QMessageBox.question(
            self,
            "Confirm Process Termination",
            f"Are you sure you want to terminate process '{name}' (PID: {pid})?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            rep = self.terminator.terminate_process(pid, reason="Manual user termination from GUI")
            if rep.status in (TerminationStatus.TERMINATED, TerminationStatus.KILLED_FORCEFULLY):
                QMessageBox.information(self, "Process Terminated", f"Successfully terminated {name} (PID: {pid}).")
                self.process_terminated.emit(pid, name)
            elif rep.status == TerminationStatus.PROTECTED_SYSTEM_PROCESS:
                QMessageBox.warning(self, "Action Denied", f"Process '{name}' is a protected system service and cannot be terminated.")
            else:
                QMessageBox.critical(self, "Termination Failed", f"Could not terminate PID {pid}: {rep.details}")

