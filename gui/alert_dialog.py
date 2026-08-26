"""
gui/alert_dialog.py

Phase 13: Interactive Threat Alert Prompt Dialog.

High-impact popup window shown when ransomware-like activity is detected.
Allows the user to immediately Terminate the offending process, Ignore it for now,
or Whitelist it permanently.
"""

from typing import Callable, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ml.detector import DetectionResult, ThreatLevel
from utils.logger import get_logger

logger = get_logger("alert_dialog")


class ThreatAlertDialog(QDialog):
    """
    Modal alert window displaying threat intelligence and prompt actions.
    """

    action_selected = Signal(str, int, str)  # action ("terminate"|"ignore"|"whitelist"), pid, name

    def __init__(
        self,
        detection_result: DetectionResult,
        parent: Optional[QWidget] = None,
        on_action: Optional[Callable[[str, DetectionResult], None]] = None,
    ):
        super().__init__(parent)
        self.detection_result = detection_result
        self.on_action = on_action
        self.user_choice: Optional[str] = None

        self.setWindowTitle("🚨 Security Alert - Ransomware Activity Detected")
        self.setFixedSize(540, 480)
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint | Qt.CustomizeWindowHint | Qt.WindowTitleHint)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # -------------------------------------------------------------------
        # Header Banner
        # -------------------------------------------------------------------
        is_critical = self.detection_result.threat_level == ThreatLevel.CRITICAL
        header_bg = "#d93025" if is_critical else "#e37400"
        header_text = "CRITICAL RANSOMWARE THREAT" if is_critical else "SUSPICIOUS BEHAVIOR DETECTED"

        header_frame = QFrame()
        header_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {header_bg};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        header_layout = QVBoxLayout(header_frame)
        title_label = QLabel(f"⚠️ {header_text}")
        title_label.setFont(QFont("Arial", 14, QFont.Bold))
        title_label.setStyleSheet("color: white;")
        title_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(title_label)

        sub_label = QLabel(f"AI Confidence Score: {self.detection_result.confidence * 100:.1f}%")
        sub_label.setFont(QFont("Arial", 11))
        sub_label.setStyleSheet("color: #ffffff;")
        sub_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(sub_label)

        layout.addWidget(header_frame)

        # -------------------------------------------------------------------
        # Process Information Card
        # -------------------------------------------------------------------
        proc_group = QGroupBox("Offending Process Information")
        proc_group.setFont(QFont("Arial", 10, QFont.Bold))
        proc_layout = QVBoxLayout(proc_group)

        pid = self.detection_result.suspect_pid or "Unknown"
        pname = self.detection_result.suspect_name or "Unknown Process"

        proc_info = QLabel(
            f"<b>Process Name:</b> <span style='color: #d93025; font-size: 13px;'>{pname}</span><br>"
            f"<b>Process PID:</b> <code>{pid}</code><br>"
            f"<b>Threat Rating:</b> <b>{self.detection_result.threat_level.value}</b>"
        )
        proc_info.setFont(QFont("Arial", 10))
        proc_info.setTextFormat(Qt.RichText)
        proc_layout.addWidget(proc_info)

        layout.addWidget(proc_group)

        # -------------------------------------------------------------------
        # Behavioral Indicators Breakdown
        # -------------------------------------------------------------------
        feat_group = QGroupBox("Behavioral Threat Signatures")
        feat_group.setFont(QFont("Arial", 10, QFont.Bold))
        feat_layout = QVBoxLayout(feat_group)

        f = self.detection_result.features
        ops = f.get("total_operations", 0)
        renames = f.get("num_renamed", 0)
        mods = f.get("num_modified", 0)
        rate = f.get("operation_rate_per_sec", 0.0)
        ratio = f.get("rename_modify_ratio", 0.0)

        details_text = (
            f"• Rapid File Operations: <b>{ops:.0f}</b> ops ({rate:.1f} ops/sec)\n"
            f"• Mass File Renames: <b>{renames:.0f}</b> files renamed / appended\n"
            f"• Content Overwrites: <b>{mods:.0f}</b> modifications in 10s window\n"
            f"• Rename-to-Modify Ratio: <b>{ratio:.2f}</b> (High characteristic of ransomware)"
        )
        details_label = QLabel(details_text)
        details_label.setFont(QFont("Arial", 9))
        details_label.setTextFormat(Qt.RichText)
        feat_layout.addWidget(details_label)

        layout.addWidget(feat_group)

        # -------------------------------------------------------------------
        # Action Buttons
        # -------------------------------------------------------------------
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        # Terminate Button (Red, prominent)
        self.btn_terminate = QPushButton("🛑 Terminate Process")
        self.btn_terminate.setFont(QFont("Arial", 11, QFont.Bold))
        self.btn_terminate.setCursor(Qt.PointingHandCursor)
        self.btn_terminate.setStyleSheet("""
            QPushButton {
                background-color: #d93025;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 16px;
            }
            QPushButton:hover {
                background-color: #b31412;
            }
            QPushButton:pressed {
                background-color: #8c0f0d;
            }
        """)
        self.btn_terminate.clicked.connect(self._on_terminate_clicked)
        btn_layout.addWidget(self.btn_terminate)

        # Ignore Button (Neutral)
        self.btn_ignore = QPushButton("⚪ Ignore & Allow")
        self.btn_ignore.setFont(QFont("Arial", 10))
        self.btn_ignore.setCursor(Qt.PointingHandCursor)
        self.btn_ignore.setStyleSheet("""
            QPushButton {
                background-color: #5f6368;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 14px;
            }
            QPushButton:hover {
                background-color: #494c50;
            }
        """)
        self.btn_ignore.clicked.connect(self._on_ignore_clicked)
        btn_layout.addWidget(self.btn_ignore)

        # Whitelist Button
        self.btn_whitelist = QPushButton("🛡️ Whitelist")
        self.btn_whitelist.setFont(QFont("Arial", 10))
        self.btn_whitelist.setCursor(Qt.PointingHandCursor)
        self.btn_whitelist.setStyleSheet("""
            QPushButton {
                background-color: #1a73e8;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 14px;
            }
            QPushButton:hover {
                background-color: #1557b0;
            }
        """)
        self.btn_whitelist.clicked.connect(self._on_whitelist_clicked)
        btn_layout.addWidget(self.btn_whitelist)

        layout.addLayout(btn_layout)

    def _on_terminate_clicked(self):
        self.user_choice = "terminate"
        pid = self.detection_result.suspect_pid or 0
        name = self.detection_result.suspect_name or "unknown"
        self.action_selected.emit("terminate", pid, name)
        if self.on_action:
            self.on_action("terminate", self.detection_result)
        self.accept()

    def _on_ignore_clicked(self):
        self.user_choice = "ignore"
        pid = self.detection_result.suspect_pid or 0
        name = self.detection_result.suspect_name or "unknown"
        self.action_selected.emit("ignore", pid, name)
        if self.on_action:
            self.on_action("ignore", self.detection_result)
        self.accept()

    def _on_whitelist_clicked(self):
        self.user_choice = "whitelist"
        pid = self.detection_result.suspect_pid or 0
        name = self.detection_result.suspect_name or "unknown"
        self.action_selected.emit("whitelist", pid, name)
        if self.on_action:
            self.on_action("whitelist", self.detection_result)
        self.accept()

