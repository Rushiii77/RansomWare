"""
gui/pages/dashboard_page.py

Phase 14: System Overview & Telemetry Dashboard Page.

Displays protection state, threat statistics, live Matplotlib trend charts,
risk score gauge, and recent activity feed.
"""

from collections import deque
import time
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import matplotlib
matplotlib.use("QtAgg")
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from database.db_manager import DatabaseManager
from ml.detector import DetectionResult, ThreatLevel


class DashboardPage(QWidget):
    """Main cybersecurity dashboard."""

    toggle_protection_requested = Signal()

    def __init__(self, db: DatabaseManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.db = db

        # History for live Matplotlib graphs (last 30 ticks)
        self.timestamps = deque(maxlen=30)
        self.ops_history = deque(maxlen=30)
        self.risk_history = deque(maxlen=30)

        for i in range(30):
            self.timestamps.append(i)
            self.ops_history.append(0.0)
            self.risk_history.append(0.0)

        self._init_ui()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # -------------------------------------------------------------------
        # Row 1: Protection Status Banner & Stat Cards
        # -------------------------------------------------------------------
        top_layout = QHBoxLayout()
        top_layout.setSpacing(15)

        # Banner Card
        self.status_card = QFrame()
        self.status_card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        status_layout = QVBoxLayout(self.status_card)

        self.status_label = QLabel("● SHIELD ACTIVE & PROTECTED")
        self.status_label.setFont(QFont("Arial", 13, QFont.Bold))
        self.status_label.setStyleSheet("color: #22c55e;")
        status_layout.addWidget(self.status_label)

        sub_status = QLabel("AI Behavioral Monitor: Real-Time Endpoint Defense")
        sub_status.setFont(QFont("Arial", 9))
        sub_status.setStyleSheet("color: #94a3b8;")
        status_layout.addWidget(sub_status)

        self.btn_toggle = QPushButton("Pause Protection")
        self.btn_toggle.setFont(QFont("Arial", 9, QFont.Bold))
        self.btn_toggle.setCursor(Qt.PointingHandCursor)
        self.btn_toggle.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f8fafc;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover { background-color: #475569; }
        """)
        self.btn_toggle.clicked.connect(self.toggle_protection_requested.emit)
        status_layout.addWidget(self.btn_toggle)

        top_layout.addWidget(self.status_card, stretch=2)

        # 4 Stat Metric Cards
        self.card_procs = self._create_metric_card("Processes Monitored", "0", "#38bdf8")
        self.card_threats = self._create_metric_card("Threats Detected", "0", "#f43f5e")
        self.card_terminated = self._create_metric_card("Terminated", "0", "#e11d48")
        self.card_incidents = self._create_metric_card("Incidents Logged", "0", "#a855f7")

        top_layout.addWidget(self.card_procs, stretch=1)
        top_layout.addWidget(self.card_threats, stretch=1)
        top_layout.addWidget(self.card_terminated, stretch=1)
        top_layout.addWidget(self.card_incidents, stretch=1)

        main_layout.addLayout(top_layout)

        # -------------------------------------------------------------------
        # Row 2: Live Matplotlib Activity Graph & Risk Score Meter
        # -------------------------------------------------------------------
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(15)

        # Matplotlib Graph Frame
        graph_frame = QFrame()
        graph_frame.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border: 1px solid #1e293b;
                border-radius: 10px;
                padding: 10px;
            }
        """)
        graph_layout = QVBoxLayout(graph_frame)

        g_header = QLabel("📈 Real-Time File Operations & AI Risk Score Trend")
        g_header.setFont(QFont("Arial", 11, QFont.Bold))
        g_header.setStyleSheet("color: #e2e8f0;")
        graph_layout.addWidget(g_header)

        # Matplotlib Figure & Canvas
        self.fig = Figure(figsize=(6, 3), dpi=100, facecolor="#0f172a")
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor("#0f172a")
        self._setup_chart()
        graph_layout.addWidget(self.canvas)

        mid_layout.addWidget(graph_frame, stretch=3)

        # Risk Score Meter Card
        meter_frame = QFrame()
        meter_frame.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        meter_layout = QVBoxLayout(meter_frame)

        m_header = QLabel("🛡️ Current Endpoint Risk")
        m_header.setFont(QFont("Arial", 11, QFont.Bold))
        m_header.setStyleSheet("color: #e2e8f0;")
        meter_layout.addWidget(m_header)

        self.lbl_risk_level = QLabel("SAFE")
        self.lbl_risk_level.setFont(QFont("Arial", 22, QFont.Bold))
        self.lbl_risk_level.setAlignment(Qt.AlignCenter)
        self.lbl_risk_level.setStyleSheet("color: #22c55e;")
        meter_layout.addWidget(self.lbl_risk_level)

        self.lbl_risk_score = QLabel("Risk Score: 0 / 100")
        self.lbl_risk_score.setFont(QFont("Arial", 11))
        self.lbl_risk_score.setAlignment(Qt.AlignCenter)
        self.lbl_risk_score.setStyleSheet("color: #94a3b8;")
        meter_layout.addWidget(self.lbl_risk_score)

        self.progress_risk = QProgressBar()
        self.progress_risk.setRange(0, 100)
        self.progress_risk.setValue(0)
        self.progress_risk.setStyleSheet("""
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 6px;
                text-align: center;
                background-color: #0f172a;
                color: white;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #22c55e;
                border-radius: 5px;
            }
        """)
        meter_layout.addWidget(self.progress_risk)

        meter_layout.addSpacing(10)

        r_feed_label = QLabel("Recent Security Events")
        r_feed_label.setFont(QFont("Arial", 10, QFont.Bold))
        r_feed_label.setStyleSheet("color: #cbd5e1;")
        meter_layout.addWidget(r_feed_label)

        self.list_recent = QListWidget()
        self.list_recent.setStyleSheet("""
            QListWidget {
                background-color: #0f172a;
                border: 1px solid #334155;
                border-radius: 6px;
                color: #e2e8f0;
                font-family: monospace;
                font-size: 11px;
            }
        """)
        meter_layout.addWidget(self.list_recent)

        mid_layout.addWidget(meter_frame, stretch=2)
        main_layout.addLayout(mid_layout)

        self.refresh_stats()

    def _create_metric_card(self, title: str, init_val: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 12px;
            }
        """)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)

        lbl_title = QLabel(title)
        lbl_title.setFont(QFont("Arial", 9))
        lbl_title.setStyleSheet("color: #94a3b8;")
        layout.addWidget(lbl_title)

        lbl_val = QLabel(init_val)
        lbl_val.setFont(QFont("Arial", 18, QFont.Bold))
        lbl_val.setStyleSheet(f"color: {color_hex};")
        layout.addWidget(lbl_val)

        card.lbl_val = lbl_val  # Store reference
        return card

    def _setup_chart(self):
        self.ax.clear()
        self.ax.set_facecolor("#0f172a")
        self.ax.tick_params(colors="#64748b", labelsize=8)
        self.ax.spines["bottom"].set_color("#334155")
        self.ax.spines["top"].set_color("#0f172a")
        self.ax.spines["left"].set_color("#334155")
        self.ax.spines["right"].set_color("#0f172a")

        self.line_ops, = self.ax.plot(list(self.timestamps), list(self.ops_history), color="#38bdf8", label="File Ops / sec", linewidth=2)
        self.line_risk, = self.ax.plot(list(self.timestamps), list(self.risk_history), color="#f43f5e", label="AI Risk Score", linewidth=2, linestyle="--")

        self.ax.legend(facecolor="#1e293b", edgecolor="#334155", labelcolor="#cbd5e1", fontsize=8, loc="upper left")
        self.ax.set_ylim(0, 100)
        self.fig.tight_layout()

    def update_telemetry(self, res: DetectionResult, proc_count: int):
        """Update live telemetry, chart, and risk meter."""
        ops = res.features.get("total_operations", 0.0)
        rate = res.features.get("operation_rate_per_sec", 0.0)
        score = int(res.confidence * 100)

        # Update data queues
        self.ops_history.append(min(100.0, rate * 5.0))
        self.risk_history.append(float(score))

        # Redraw chart
        self.line_ops.set_ydata(list(self.ops_history))
        self.line_risk.set_ydata(list(self.risk_history))
        self.canvas.draw_idle()

        # Update Risk Meter
        self.lbl_risk_score.setText(f"Risk Score: {score} / 100")
        self.progress_risk.setValue(score)

        if res.threat_level == ThreatLevel.CRITICAL:
            self.lbl_risk_level.setText("CRITICAL")
            self.lbl_risk_level.setStyleSheet("color: #e11d48;")
            self.progress_risk.setStyleSheet("QProgressBar::chunk { background-color: #e11d48; }")
        elif res.threat_level == ThreatLevel.HIGH_RISK:
            self.lbl_risk_level.setText("HIGH RISK")
            self.lbl_risk_level.setStyleSheet("color: #f97316;")
            self.progress_risk.setStyleSheet("QProgressBar::chunk { background-color: #f97316; }")
        elif res.threat_level == ThreatLevel.SUSPICIOUS:
            self.lbl_risk_level.setText("SUSPICIOUS")
            self.lbl_risk_level.setStyleSheet("color: #eab308;")
            self.progress_risk.setStyleSheet("QProgressBar::chunk { background-color: #eab308; }")
        else:
            self.lbl_risk_level.setText("SAFE")
            self.lbl_risk_level.setStyleSheet("color: #22c55e;")
            self.progress_risk.setStyleSheet("QProgressBar::chunk { background-color: #22c55e; }")

        # Update proc count
        self.card_procs.lbl_val.setText(str(proc_count))

        # Add event to recent list if suspicious or threat
        if res.is_ransomware:
            ts = time.strftime("%H:%M:%S")
            item_text = f"[{ts}] 🚨 {res.threat_level.value} (PID {res.suspect_pid}: {res.suspect_name})"
            self.list_recent.insertItem(0, item_text)
            if self.list_recent.count() > 15:
                self.list_recent.takeItem(self.list_recent.count() - 1)

    def refresh_stats(self):
        stats = self.db.get_stats()
        self.card_threats.lbl_val.setText(str(stats.get("total_threats", 0)))
        self.card_terminated.lbl_val.setText(str(stats.get("terminated", 0)))
        self.card_incidents.lbl_val.setText(str(stats.get("total_threats", 0)))

    def set_protection_status(self, active: bool):
        if active:
            self.status_label.setText("● SHIELD ACTIVE & PROTECTED")
            self.status_label.setStyleSheet("color: #22c55e;")
            self.btn_toggle.setText("Pause Protection")
        else:
            self.status_label.setText("● SHIELD PAUSED")
            self.status_label.setStyleSheet("color: #94a3b8;")
            self.btn_toggle.setText("Resume Protection")

