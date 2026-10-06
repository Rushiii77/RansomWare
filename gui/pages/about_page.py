"""
gui/pages/about_page.py

About RansomShield: Architecture, Pipeline & Security Specifications.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


class AboutPage(QWidget):
    """About RansomShield: System Overview & Defense Architecture."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
        """)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(15)

        # Title Card
        title_card = QFrame()
        title_card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        tc_layout = QVBoxLayout(title_card)

        title = QLabel("🛡️ RansomShield")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setStyleSheet("color: #38bdf8;")
        tc_layout.addWidget(title)

        sub = QLabel("Autonomous Real-Time Endpoint Ransomware Defense & Process Mitigation System")
        sub.setFont(QFont("Arial", 10))
        sub.setStyleSheet("color: #94a3b8;")
        tc_layout.addWidget(sub)
        layout.addWidget(title_card)

        # Architecture & Pipeline Flow Card
        arch_card = QFrame()
        arch_card.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        ac_layout = QVBoxLayout(arch_card)

        lbl_ac_title = QLabel("Core Defense Pipeline & Telemetry Flow")
        lbl_ac_title.setFont(QFont("Arial", 12, QFont.Bold))
        lbl_ac_title.setStyleSheet("color: #e2e8f0;")
        ac_layout.addWidget(lbl_ac_title)

        flow_text = QLabel(
            "<code><b>Process Monitor (psutil)</b> + <b>File System Monitor (watchdog)</b><br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Behavioral Feature Extraction Engine</b> (11 Behavioral Metrics over 10s Rolling Window)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Threat Detection & Classification Engine</b> (Risk Probability & Confidence Assessment)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Risk Scoring Engine</b> (SAFE / SUSPICIOUS / HIGH_RISK / CRITICAL)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Automated Process Termination Engine</b> (SIGTERM with SIGKILL Fallback)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>SQLite Incident Persistence & PDF Forensic Report Generation</b></code>"
        )
        flow_text.setTextFormat(Qt.RichText)
        flow_text.setStyleSheet("color: #38bdf8; font-size: 11px; line-height: 1.6; padding: 10px;")
        ac_layout.addWidget(flow_text)
        layout.addWidget(arch_card)

        # Security Specifications Card
        specs_card = QFrame()
        specs_card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        sc_layout = QVBoxLayout(specs_card)

        lbl_sc_title = QLabel("Endpoint Protection Capabilities")
        lbl_sc_title.setFont(QFont("Arial", 12, QFont.Bold))
        lbl_sc_title.setStyleSheet("color: #38bdf8;")
        sc_layout.addWidget(lbl_sc_title)

        capabilities = [
            (
                "⚡ Real-Time File Telemetry",
                "High-frequency file system observation capturing CREATE, MODIFY, DELETE, and MOVE (rename) events without disk degradation.",
            ),
            (
                "🔍 Behavioral Analytics",
                "Evaluates rolling operation velocities, extension diversification, multi-directory traversal, and rename-to-modify ratios.",
            ),
            (
                "🛑 Two-Stage Process Mitigation",
                "Rapid termination sequence that dispatches graceful SIGTERM with a 3.0s timeout before forceful SIGKILL fallback.",
            ),
            (
                "🛡️ Critical System Whitelisting",
                "Guaranteed safeguards ensuring root OS services (PID <= 1, launchd, systemd, kernel_task) and RansomShield itself can never be terminated.",
            ),
            (
                "📄 Forensic Audit & PDF Reporting",
                "Thread-safe incident persistence with ReportLab integration for generating formal incident forensic investigation summaries.",
            ),
        ]

        for cap_title, cap_desc in capabilities:
            cap_t = QLabel(f"<b>{cap_title}</b>")
            cap_t.setFont(QFont("Arial", 10, QFont.Bold))
            cap_t.setStyleSheet("color: #f8fafc; margin-top: 6px;")
            sc_layout.addWidget(cap_t)

            cap_d = QLabel(cap_desc)
            cap_d.setFont(QFont("Arial", 9.5))
            cap_d.setWordWrap(True)
            cap_d.setStyleSheet("color: #94a3b8; margin-bottom: 6px;")
            sc_layout.addWidget(cap_d)

        layout.addWidget(specs_card)

        scroll.setWidget(container)
        main_layout.addWidget(scroll)
