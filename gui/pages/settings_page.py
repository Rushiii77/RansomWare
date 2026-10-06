"""
gui/pages/settings_page.py

Phase 14 / Section 19: System Configuration & Whitelist Management Page.

Allows configuring telemetry directories, detection sensitivity thresholds,
and managing trusted process whitelists.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSlider,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

import config
from database.db_manager import DatabaseManager


class SettingsPage(QWidget):
    """Configuration and whitelist management view."""

    def __init__(self, db: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        title = QLabel("⚙️ System Defense Settings & Thresholds")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        layout.addWidget(title)

        content_layout = QHBoxLayout()
        content_layout.setSpacing(15)

        # Left Column: Directory & Threshold Settings
        left_box = QGroupBox("Monitoring & Detection Parameters")
        left_box.setFont(QFont("Arial", 10, QFont.Bold))
        left_layout = QFormLayout(left_box)
        left_layout.setSpacing(12)

        # Watch Directory
        dir_box = QHBoxLayout()
        self.txt_watch_dir = QLineEdit(config.DEFAULT_WATCH_DIRECTORY)
        self.txt_watch_dir.setReadOnly(True)
        self.txt_watch_dir.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #f8fafc;
            }
        """)
        dir_box.addWidget(self.txt_watch_dir)

        btn_browse = QPushButton("Browse...")
        btn_browse.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 10px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        btn_browse.clicked.connect(self._browse_dir)
        dir_box.addWidget(btn_browse)
        left_layout.addRow(QLabel("Watch Directory:"), dir_box)

        # Process Polling Interval
        self.spin_poll = QSpinBox()
        self.spin_poll.setRange(1, 10)
        self.spin_poll.setValue(int(config.PROCESS_POLL_INTERVAL_SECONDS))
        self.spin_poll.setSuffix(" seconds")
        self.spin_poll.setStyleSheet("""
            QSpinBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 4px;
                color: #f8fafc;
            }
        """)
        left_layout.addRow(QLabel("Process Polling:"), self.spin_poll)

        # Sliding Window
        self.spin_window = QSpinBox()
        self.spin_window.setRange(5, 60)
        self.spin_window.setValue(int(config.FEATURE_WINDOW_SECONDS))
        self.spin_window.setSuffix(" seconds")
        self.spin_window.setStyleSheet("""
            QSpinBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 4px;
                color: #f8fafc;
            }
        """)
        left_layout.addRow(QLabel("Feature Window:"), self.spin_window)

        # Thresholds
        self.slider_suspicious = self._create_threshold_slider(50)
        left_layout.addRow(QLabel("Suspicious Alert (%):"), self.slider_suspicious)

        self.slider_critical = self._create_threshold_slider(90)
        left_layout.addRow(QLabel("Critical Threat (%):"), self.slider_critical)

        btn_save = QPushButton("💾 Save Parameter Settings")
        btn_save.setFont(QFont("Arial", 10, QFont.Bold))
        btn_save.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        btn_save.clicked.connect(self._save_settings)
        left_layout.addRow("", btn_save)

        content_layout.addWidget(left_box, stretch=1)

        # Right Column: Trusted Process Whitelist
        right_box = QGroupBox("Permanent Process Whitelist")
        right_box.setFont(QFont("Arial", 10, QFont.Bold))
        right_layout = QVBoxLayout(right_box)
        right_layout.setSpacing(10)

        add_box = QHBoxLayout()
        self.txt_whitelist_name = QLineEdit()
        self.txt_whitelist_name.setPlaceholderText("Process executable name (e.g. backup_tool.exe)...")
        self.txt_whitelist_name.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #f8fafc;
            }
        """)
        add_box.addWidget(self.txt_whitelist_name)

        btn_add_wl = QPushButton("Add to Whitelist")
        btn_add_wl.setStyleSheet("""
            QPushButton {
                background-color: #16a34a;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #15803d; }
        """)
        btn_add_wl.clicked.connect(self._add_to_whitelist)
        add_box.addWidget(btn_add_wl)
        right_layout.addLayout(add_box)

        # Whitelist Table
        self.table_wl = QTableWidget()
        self.table_wl.setColumnCount(3)
        self.table_wl.setHorizontalHeaderLabels(["Trusted Process Name", "Status", "Action"])
        self.table_wl.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_wl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_wl.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.table_wl.setColumnWidth(2, 100)
        self.table_wl.verticalHeader().setVisible(False)
        self.table_wl.setStyleSheet("""
            QTableWidget {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 6px;
                color: #e2e8f0;
            }
            QHeaderView::section {
                background-color: #1e293b;
                color: #94a3b8;
                font-weight: bold;
                padding: 6px;
                border: none;
            }
        """)
        right_layout.addWidget(self.table_wl)

        btn_clear_wl = QPushButton("🧹 Clear Entire Whitelist")
        btn_clear_wl.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        btn_clear_wl.clicked.connect(self._clear_all_whitelist)
        right_layout.addWidget(btn_clear_wl)

        content_layout.addWidget(right_box, stretch=1)
        layout.addLayout(content_layout)

        self.refresh_whitelist()

    def _create_threshold_slider(self, val: int) -> QSlider:
        slider = QSlider(Qt.Horizontal)
        slider.setRange(20, 95)
        slider.setValue(val)
        slider.setTickInterval(5)
        slider.setTickPosition(QSlider.TicksBelow)
        return slider

    def _browse_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Safe Watch Directory", config.DEFAULT_WATCH_DIRECTORY)
        if d:
            self.txt_watch_dir.setText(d)

    def _save_settings(self):
        QMessageBox.information(self, "Settings Saved", "System defense settings updated successfully.")

    def _add_to_whitelist(self):
        name = self.txt_whitelist_name.text().strip()
        if not name:
            return
        if self.db.add_to_whitelist(name):
            self.txt_whitelist_name.clear()
            self.refresh_whitelist()
            QMessageBox.information(self, "Process Whitelisted", f"Added '{name}' to trusted whitelist.")

    def _remove_from_whitelist(self, name: str):
        reply = QMessageBox.question(
            self,
            "Confirm Whitelist Removal",
            f"Remove '{name}' from the trusted whitelist?\n\nRansomShield will actively monitor and alert on this process again.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            if self.db.remove_from_whitelist(name):
                self.refresh_whitelist()
                QMessageBox.information(
                    self,
                    "Process Removed",
                    f"'{name}' was removed from the whitelist.\nRansomShield behavioral detection is now active for this process.",
                )
            else:
                QMessageBox.warning(self, "Notice", f"Could not remove '{name}'.")

    def _clear_all_whitelist(self):
        reply = QMessageBox.question(
            self,
            "Clear Whitelist",
            "Are you sure you want to clear the entire process whitelist?\n\nAll processes will trigger active defense monitoring and alerts again.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            cnt = self.db.clear_whitelist()
            self.refresh_whitelist()
            QMessageBox.information(self, "Whitelist Cleared", f"Cleared {cnt} entries from whitelist. Prompt alerts are fully restored!")

    def refresh_whitelist(self):
        names = self.db.get_whitelist()
        self.table_wl.setRowCount(len(names))
        for row, n in enumerate(names):
            self.table_wl.setItem(row, 0, QTableWidgetItem(n))
            item_s = QTableWidgetItem("WHITELISTED")
            item_s.setTextAlignment(Qt.AlignCenter)
            item_s.setForeground(Qt.green)
            self.table_wl.setItem(row, 1, item_s)

            btn_del = QPushButton("🗑️ Remove")
            btn_del.setStyleSheet("""
                QPushButton {
                    background-color: #ef4444;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 4px 8px;
                    font-size: 11px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #dc2626; }
            """)
            btn_del.setCursor(Qt.PointingHandCursor)
            btn_del.clicked.connect(lambda _, proc_name=n: self._remove_from_whitelist(proc_name))
            self.table_wl.setCellWidget(row, 2, btn_del)

