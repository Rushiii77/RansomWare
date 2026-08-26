"""
gui/pages/about_page.py

Phase 18 / Sections 41 & 42: Academic Project Presentation & Viva Defense Page.

Presents complete project documentation, system architecture flow, and built-in
examiner Viva Q&A responses as specified in the project definition.
"""

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class AboutPage(QWidget):
    """Academic project documentation and Viva defense guide."""

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

        title = QLabel("🛡️ AI-Based Ransomware Detection & Process Termination System")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setStyleSheet("color: #38bdf8;")
        tc_layout.addWidget(title)

        sub = QLabel("Final-Year Cybersecurity Engineering Major Project | Defensive Endpoint Security Prototype")
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

        lbl_ac_title = QLabel("System Architecture & Core Defense Pipeline")
        lbl_ac_title.setFont(QFont("Arial", 12, QFont.Bold))
        lbl_ac_title.setStyleSheet("color: #e2e8f0;")
        ac_layout.addWidget(lbl_ac_title)

        flow_text = QLabel(
            "<code><b>Process Monitor (psutil)</b> + <b>File Monitor (watchdog)</b><br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Feature Extraction Engine</b> (11 Behavioral Metrics over 10s Rolling Window)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Machine Learning Model</b> (Random Forest Classifier: 100 Trees, Depth 12)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Risk Scoring Engine</b> (0–100 Score & Confidence Rating)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>Interactive Alert / Response Engine</b> (Graceful SIGTERM / SIGKILL Fallback)<br>"
            "&nbsp;&nbsp;&nbsp;&nbsp;↓<br>"
            "<b>SQLite Incident Persistence & PDF ReportLab Forensic Reports</b></code>"
        )
        flow_text.setTextFormat(Qt.RichText)
        flow_text.setStyleSheet("color: #38bdf8; font-size: 11px; line-height: 1.5; padding: 10px;")
        ac_layout.addWidget(flow_text)
        layout.addWidget(arch_card)

        # Viva Defense Q&A Card
        viva_card = QFrame()
        viva_card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 16px;
            }
        """)
        vc_layout = QVBoxLayout(viva_card)

        lbl_vc_title = QLabel("🎓 Key Viva Defense Questions & Technical Explanations")
        lbl_vc_title.setFont(QFont("Arial", 12, QFont.Bold))
        lbl_vc_title.setStyleSheet("color: #f59e0b;")
        vc_layout.addWidget(lbl_vc_title)

        viva_qa = [
            (
                "Q1: How does AI / Machine Learning detect ransomware?",
                "The system continuously monitors behavioral telemetry (file operations, rapid content modifications, "
                "extension renames, multi-directory traversals, and CPU load). These telemetry metrics are converted into "
                "a fixed-size mathematical feature vector. The trained Random Forest classifier evaluates the combination of "
                "these behavioral patterns simultaneously to produce a threat probability and risk score."
            ),
            (
                "Q2: Why use Machine Learning instead of traditional antivirus signatures?",
                "Traditional antivirus relies on static hashes and known signatures, which zero-day ransomware or polymorphism can "
                "easily bypass. Behavioral Machine Learning identifies the fundamental, unavoidable operational signature of ransomware "
                "— rapid batch file encryption and renaming — regardless of whether the malicious binary has been seen before."
            ),
            (
                "Q3: Can your system recover encrypted files?",
                "No. The system is designed for early detection and process-level mitigation. Terminating the offending process "
                "stops encryption immediately and preserves the rest of the file system, but it cannot reverse encryption that has already taken place."
            ),
            (
                "Q4: Is this actual ransomware or harmful to the computer?",
                "No. The prototype is strictly defensive and academic. It contains zero destructive encryption algorithms. "
                "All testing is performed using a controlled behavioral simulator confined strictly inside the sandbox folder."
            ),
            (
                "Q5: How does the system prevent false positives during heavy developer builds?",
                "The Random Forest model is trained on diverse benign workloads including software compilation and package installations. "
                "Legitimate compiler activity modifies files but does not exhibit mass extension-appending renames with high rename-to-modify ratios."
            )
        ]

        for q, a in viva_qa:
            q_lbl = QLabel(f"<b>{q}</b>")
            q_lbl.setFont(QFont("Arial", 10, QFont.Bold))
            q_lbl.setStyleSheet("color: #38bdf8; margin-top: 8px;")
            vc_layout.addWidget(q_lbl)

            a_lbl = QLabel(a)
            a_lbl.setFont(QFont("Arial", 9.5))
            a_lbl.setWordWrap(True)
            a_lbl.setStyleSheet("color: #cbd5e1; margin-bottom: 6px; line-height: 1.4;")
            vc_layout.addWidget(a_lbl)

        layout.addWidget(viva_card)

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

