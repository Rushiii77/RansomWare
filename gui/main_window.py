"""
gui/main_window.py

Phases 13, 14 & 16: Full Desktop Cybersecurity Application Main Window.

Assembles the 9 modular pages into a sleek, responsive dark-themed cybersecurity
command center with real-time background telemetry integration.
"""

import sys
import time
from typing import Optional

from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

import config
from database.db_manager import DatabaseManager
from gui.alert_dialog import ThreatAlertDialog
from gui.pages.about_page import AboutPage
from gui.pages.activity_page import LiveActivityPage
from gui.pages.alerts_page import AlertsPage
from gui.pages.dashboard_page import DashboardPage
from gui.pages.incidents_page import IncidentsPage
from gui.pages.ml_page import MLModelPage
from gui.pages.processes_page import ProcessesPage
from gui.pages.reports_page import ReportsPage
from gui.pages.settings_page import SettingsPage
from ml.detector import DetectionResult, RansomwareDetector, ThreatLevel
from monitoring.file_monitor import FileMonitor
from monitoring.process_monitor import ProcessMonitor
from response.process_terminator import ProcessTerminator
from simulator.safe_ransomware_simulator import SafeRansomwareSimulator
from utils.logger import get_logger

logger = get_logger("main_window")


class TelemetryWorker(QThread):
    """Background polling thread feeding telemetry to GUI without blocking."""

    telemetry_updated = Signal(object, list, list)  # DetectionResult, list[ProcessSnapshot], list[FileEvent]
    threat_triggered = Signal(object)              # DetectionResult

    def __init__(
        self,
        detector: RansomwareDetector,
        file_monitor: FileMonitor,
        process_monitor: ProcessMonitor,
    ):
        super().__init__()
        self.detector = detector
        self.file_monitor = file_monitor
        self.process_monitor = process_monitor
        self._running = True
        self._paused = False

    def run(self):
        self.process_monitor.start()
        self.file_monitor.start()

        while self._running:
            try:
                if not self._paused:
                    events = self.file_monitor.get_recent_events(seconds=2.0)
                    procs = self.process_monitor.get_all_processes()
                    res = self.detector.evaluate_live(self.file_monitor, self.process_monitor)

                    self.telemetry_updated.emit(res, procs, events)

                    if res.is_ransomware:
                        self.threat_triggered.emit(res)

            except Exception:
                logger.exception("Error in TelemetryWorker cycle.")

            time.sleep(1.5)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def stop(self):
        self._running = False
        self.file_monitor.stop()
        self.process_monitor.stop()
        self.wait(timeout=2000)


class MainWindow(QMainWindow):
    """Primary Desktop Application Window."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI-Based Ransomware Detection & Process Termination System")
        self.resize(1240, 840)
        self.setMinimumSize(1000, 700)

        # Core Backend Components
        self.db = DatabaseManager()
        self.terminator = ProcessTerminator()
        self.detector = RansomwareDetector()
        self.file_monitor = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
        self.process_monitor = ProcessMonitor(poll_interval=config.PROCESS_POLL_INTERVAL_SECONDS)

        self.session_ignored_pids = set()
        self._is_protected = True
        self._alert_active = False

        self._apply_dark_theme()
        self._init_ui()
        self._start_telemetry_worker()

    def _apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0b0f19;
                color: #f8fafc;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            }
            QScrollBar:vertical {
                border: none;
                background: #0f172a;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #334155;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical:hover {
                background: #475569;
            }
        """)

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # -------------------------------------------------------------------
        # 1. Left Sidebar Navigation
        # -------------------------------------------------------------------
        sidebar = QFrame()
        sidebar.setFixedWidth(240)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border-right: 1px solid #1e293b;
            }
        """)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(6)

        # App Brand Header
        brand_box = QHBoxLayout()
        brand_title = QLabel("🛡️ ANTIVIRUS AI")
        brand_title.setFont(QFont("Arial", 13, QFont.Bold))
        brand_title.setStyleSheet("color: #38bdf8;")
        brand_box.addWidget(brand_title)
        sidebar_layout.addLayout(brand_box)

        brand_sub = QLabel("Ransomware Defense Shield")
        brand_sub.setFont(QFont("Arial", 8))
        brand_sub.setStyleSheet("color: #64748b; margin-bottom: 12px;")
        sidebar_layout.addWidget(brand_sub)

        # Nav Buttons Group
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        nav_items = [
            ("📊 Dashboard", 0),
            ("🔍 Active Processes", 1),
            ("📁 Live File Activity", 2),
            ("🚨 Threat Alerts", 3),
            ("📜 Incident History", 4),
            ("📄 Forensic Reports", 5),
            ("🧠 ML Model & Features", 6),
            ("⚙️ Defense Settings", 7),
            ("ℹ️ About & Viva Defense", 8),
        ]

        self.nav_buttons = []
        for text, idx in nav_items:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setFont(QFont("Arial", 10))
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 9px 14px;
                    border: none;
                    border-radius: 6px;
                    color: #94a3b8;
                    background-color: transparent;
                }
                QPushButton:hover {
                    background-color: #1e293b;
                    color: #f8fafc;
                }
                QPushButton:checked {
                    background-color: #2563eb;
                    color: white;
                    font-weight: bold;
                }
            """)
            btn.clicked.connect(lambda _, index=idx: self.stack.setCurrentIndex(index))
            self.nav_group.addButton(btn, idx)
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        self.nav_buttons[0].setChecked(True)

        sidebar_layout.addStretch()

        # Quick Test Trigger Button
        btn_sim_attack = QPushButton("🧪 Run Test Burst Attack")
        btn_sim_attack.setFont(QFont("Arial", 9, QFont.Bold))
        btn_sim_attack.setCursor(Qt.PointingHandCursor)
        btn_sim_attack.setStyleSheet("""
            QPushButton {
                background-color: #e11d48;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 10px 12px;
            }
            QPushButton:hover { background-color: #be123c; }
        """)
        btn_sim_attack.clicked.connect(self._run_test_simulation)
        sidebar_layout.addWidget(btn_sim_attack)

        root_layout.addWidget(sidebar)

        # -------------------------------------------------------------------
        # 2. Central Pages Stack
        # -------------------------------------------------------------------
        self.stack = QStackedWidget()

        # Instantiate 9 Pages
        self.page_dashboard = DashboardPage(self.db)
        self.page_dashboard.toggle_protection_requested.connect(self._toggle_protection)

        self.page_processes = ProcessesPage(self.terminator)
        self.page_processes.process_terminated.connect(self._handle_manual_terminate)

        self.page_activity = LiveActivityPage()

        self.page_alerts = AlertsPage(self.terminator)
        self.page_alerts.action_triggered.connect(self._handle_alert_action)

        self.page_incidents = IncidentsPage(self.db)
        self.page_reports = ReportsPage(self.db)
        self.page_ml = MLModelPage()
        self.page_settings = SettingsPage(self.db)
        self.page_about = AboutPage()

        self.stack.addWidget(self.page_dashboard)   # 0
        self.stack.addWidget(self.page_processes)   # 1
        self.stack.addWidget(self.page_activity)    # 2
        self.stack.addWidget(self.page_alerts)      # 3
        self.stack.addWidget(self.page_incidents)   # 4
        self.stack.addWidget(self.page_reports)     # 5
        self.stack.addWidget(self.page_ml)          # 6
        self.stack.addWidget(self.page_settings)    # 7
        self.stack.addWidget(self.page_about)       # 8

        root_layout.addWidget(self.stack)

    def _start_telemetry_worker(self):
        self.worker = TelemetryWorker(self.detector, self.file_monitor, self.process_monitor)
        self.worker.telemetry_updated.connect(self._on_telemetry_updated)
        self.worker.threat_triggered.connect(self._on_threat_triggered)
        self.worker.start()

    def _on_telemetry_updated(self, res: DetectionResult, procs: list, events: list):
        self.page_dashboard.update_telemetry(res, len(procs))
        self.page_processes.update_processes(procs)
        self.page_activity.add_events(events)

    def _on_threat_triggered(self, res: DetectionResult):
        pid = res.suspect_pid
        name = res.suspect_name

        if pid in self.session_ignored_pids:
            return
        if self.db.is_whitelisted(name):
            return
        if self._alert_active:
            return

        self.page_alerts.add_alert(res)
        self.page_dashboard.refresh_stats()

        # Display Interactive Popup
        self._alert_active = True
        dialog = ThreatAlertDialog(res, parent=self, on_action=self._handle_user_decision)
        dialog.exec()
        self._alert_active = False

        self.page_dashboard.refresh_stats()
        self.page_incidents.load_incidents()
        self.page_reports.refresh_pdf_list()

    def _handle_user_decision(self, action: str, res: DetectionResult):
        pid = res.suspect_pid or 0
        name = res.suspect_name or "unknown"

        if action == "terminate":
            rep = self.terminator.terminate_process(pid, reason=f"GUI Prompt Termination for {res.threat_level.value}")
            self.db.record_incident(
                threat_level=res.threat_level.value,
                confidence=res.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken=f"TERMINATED ({rep.status.value})",
                features=res.features,
                details=rep.details,
            )
            QMessageBox.information(self, "Process Terminated", f"Successfully terminated {name} (PID: {pid}). File system secured.")

        elif action == "ignore":
            if pid > 0:
                self.session_ignored_pids.add(pid)
            self.db.record_incident(
                threat_level=res.threat_level.value,
                confidence=res.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken="IGNORED_BY_USER",
                features=res.features,
                details="User ignored alert in GUI prompt.",
            )

        elif action == "whitelist":
            self.db.add_to_whitelist(name)
            if pid > 0:
                self.session_ignored_pids.add(pid)
            self.db.record_incident(
                threat_level=res.threat_level.value,
                confidence=res.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken="PERMANENTLY_WHITELISTED",
                features=res.features,
                details="User added to permanent whitelist.",
            )
            self.page_settings.refresh_whitelist()
            QMessageBox.information(self, "Process Whitelisted", f"Added '{name}' to trusted whitelist.")

    def _handle_alert_action(self, action: str, pid: int, name: str):
        if action == "terminate" and pid > 0:
            rep = self.terminator.terminate_process(pid, reason="Terminated from Alerts Page")
            self.db.record_incident("MANUAL", 1.0, pid, name, f"TERMINATED ({rep.status.value})", details=rep.details)
            self.page_dashboard.refresh_stats()
            self.page_incidents.load_incidents()
            QMessageBox.information(self, "Process Terminated", f"Terminated {name} (PID {pid}).")

    def _handle_manual_terminate(self, pid: int, name: str):
        self.db.record_incident("MANUAL_USER", 1.0, pid, name, "TERMINATED_FROM_PROCESS_PAGE", details="User manual kill")
        self.page_dashboard.refresh_stats()
        self.page_incidents.load_incidents()

    def _toggle_protection(self):
        self._is_protected = not self._is_protected
        if self._is_protected:
            self.worker.resume()
        else:
            self.worker.pause()
        self.page_dashboard.set_protection_status(self._is_protected)

    def _run_test_simulation(self):
        sim = SafeRansomwareSimulator(num_files=35)
        QTimer.singleShot(200, sim.run_full_simulation)
        QMessageBox.information(
            self,
            "Simulation Started",
            "Safe simulation burst initiated inside test_environment/.\nWatch the Live Activity and Dashboard charts react!",
        )

    def closeEvent(self, event):
        self.worker.stop()
        event.accept()


def launch_main_gui():
    """Launch the main desktop application."""
    app = QApplication.instance() or QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(launch_main_gui())

