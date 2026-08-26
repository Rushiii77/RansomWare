"""
gui/pages/activity_page.py

Phase 14 / Section 22: Live File-System Activity Streaming Page.

Displays real-time Watchdog file-system events (CREATE, MODIFY, DELETE, RENAME)
allowing examiners and users to observe file activity bursts directly.
"""

from collections import deque
import time
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from monitoring.file_monitor import FileEvent


class LiveActivityPage(QWidget):
    """Live stream of file-system events."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._events: deque[FileEvent] = deque(maxlen=200)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header Bar
        top_bar = QHBoxLayout()

        title = QLabel("📁 Real-Time File System Activity Stream")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        top_bar.addWidget(title)

        top_bar.addStretch()

        self.auto_scroll_cb = QCheckBox("Auto-Scroll")
        self.auto_scroll_cb.setChecked(True)
        self.auto_scroll_cb.setStyleSheet("color: #94a3b8;")
        top_bar.addWidget(self.auto_scroll_cb)

        self.btn_clear = QPushButton("Clear Stream")
        self.btn_clear.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        self.btn_clear.clicked.connect(self.clear_stream)
        top_bar.addWidget(self.btn_clear)

        layout.addLayout(top_bar)

        # Event Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Time", "Event Type", "Target File Path", "Rename / Extra Destination"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 8px;
                gridline-color: #1e293b;
                color: #e2e8f0;
                font-family: monospace;
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

    def add_events(self, events: List[FileEvent]):
        """Append newly detected file events."""
        if not events:
            return

        for e in events:
            self._events.append(e)

        self._render_table()

    def _render_table(self):
        self.table.setRowCount(len(self._events))

        event_colors = {
            "created": "#38bdf8",   # Blue
            "modified": "#fbbf24",  # Amber
            "moved": "#f43f5e",     # Red (Rename)
            "deleted": "#94a3b8",   # Gray
        }

        for row, e in enumerate(self._events):
            t_str = time.strftime("%H:%M:%S", time.localtime(e.timestamp))

            item_time = QTableWidgetItem(t_str)
            item_time.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, item_time)

            etype_str = e.event_type.upper()
            item_type = QTableWidgetItem(etype_str)
            item_type.setTextAlignment(Qt.AlignCenter)
            item_type.setForeground(QColor(event_colors.get(e.event_type, "#e2e8f0")))
            item_type.setFont(QFont("Arial", 9, QFont.Bold))
            self.table.setItem(row, 1, item_type)

            self.table.setItem(row, 2, QTableWidgetItem(e.src_path))
            self.table.setItem(row, 3, QTableWidgetItem(e.dest_path or "—"))

        if self.auto_scroll_cb.isChecked() and self._events:
            self.table.scrollToBottom()

    def clear_stream(self):
        self._events.clear()
        self.table.setRowCount(0)

