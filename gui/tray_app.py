"""
gui/tray_app.py

Phase 13: Background System Tray / Menu Bar Antivirus Application.

Runs silently in the macOS Menu Bar / Windows System Tray, continuously
monitoring the operating system for ransomware behavioral patterns.
When anomalous behavior is detected, pops up an interactive Terminate/Ignore prompt.
"""

import sys
import time
from typing import Optional, Set

from PySide6.QtCore import QObject, QThread, Qt, Signal, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
    QWidget,
)

import config
from database.db_manager import DatabaseManager
from gui.alert_dialog import ThreatAlertDialog
from ml.detector import DetectionResult, RansomwareDetector, ThreatLevel
from monitoring.file_monitor import FileMonitor
from monitoring.process_monitor import ProcessMonitor
from response.process_terminator import ProcessTerminator, TerminationStatus
from simulator.safe_ransomware_simulator import SafeRansomwareSimulator
from utils.logger import get_logger

logger = get_logger("tray_app")


def create_shield_icon(color_hex: str, label: str = "🛡️") -> QIcon:
    """Create a clean vector shield icon dynamically with QPainter."""
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    # Circle background
    painter.setBrush(QColor(color_hex))
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(4, 4, 56, 56)

    # Inner badge
    painter.setPen(QColor("white"))
    font = QFont("Arial", 26, QFont.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), Qt.AlignCenter, "S")
    painter.end()

    return QIcon(pixmap)


class ShieldWorker(QThread):
    """Background telemetry and AI detection loop."""

    threat_detected = Signal(DetectionResult)
    status_updated = Signal(str, int, float)  # status_text, process_count, max_cpu

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
        logger.info("Background AI shield monitoring worker started.")
        self.process_monitor.start()
        self.file_monitor.start()

        while self._running:
            try:
                if not self._paused:
                    res = self.detector.evaluate_live(self.file_monitor, self.process_monitor)
                    procs = self.process_monitor.get_all_processes()
                    max_cpu = max((p.cpu_percent for p in procs), default=0.0)

                    self.status_updated.emit(res.threat_level.value, len(procs), max_cpu)

                    if res.is_ransomware:
                        self.threat_detected.emit(res)

            except Exception:
                logger.exception("Error in background shield worker cycle.")

            time.sleep(2.0)

    def pause(self):
        self._paused = True
        logger.info("AI shield worker paused.")

    def resume(self):
        self._paused = False
        logger.info("AI shield worker resumed.")

    def stop(self):
        self._running = False
        self.file_monitor.stop()
        self.process_monitor.stop()
        self.wait(timeout=3000)


class SystemTrayShieldApp(QObject):
    """
    Main system tray controller.
    """

    def __init__(self, app: QApplication):
        super().__init__()
        self.app = app
        self.db = DatabaseManager()
        self.terminator = ProcessTerminator()
        self.detector = RansomwareDetector()
        self.file_monitor = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
        self.process_monitor = ProcessMonitor(poll_interval=config.PROCESS_POLL_INTERVAL_SECONDS)

        self.session_ignored_pids: Set[int] = set()
        self.active_alert_dialog: Optional[ThreatAlertDialog] = None

        self._init_tray_icon()
        self._init_worker()

    def _init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.icon_safe = create_shield_icon("#1b8738")       # Green
        self.icon_threat = create_shield_icon("#d93025")     # Red
        self.icon_paused = create_shield_icon("#5f6368")     # Gray

        self.tray_icon.setIcon(self.icon_safe)
        self.tray_icon.setToolTip("AI Ransomware Shield: Active & Protected")

        # Context Menu
        menu = QMenu()

        self.status_action = QAction("🛡️ Shield: Active (Protected)", self)
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)

        menu.addSeparator()

        self.action_sim = QAction("🚨 Run Safe Test Simulation Burst", self)
        self.action_sim.triggered.connect(self._trigger_test_simulation)
        menu.addAction(self.action_sim)

        self.action_history = QAction("📜 View Recent Incident Log", self)
        self.action_history.triggered.connect(self._show_incident_history)
        menu.addAction(self.action_history)

        menu.addSeparator()

        self.action_toggle = QAction("⏸️ Pause Protection", self)
        self.action_toggle.triggered.connect(self._toggle_protection)
        menu.addAction(self.action_toggle)

        menu.addSeparator()

        self.action_quit = QAction("🚪 Quit Antivirus Shield", self)
        self.action_quit.triggered.connect(self._quit_app)
        menu.addAction(self.action_quit)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()

        logger.info("System tray icon initialized.")

    def _init_worker(self):
        self.worker = ShieldWorker(self.detector, self.file_monitor, self.process_monitor)
        self.worker.threat_detected.connect(self._handle_threat_detected)
        self.worker.status_updated.connect(self._handle_status_update)
        self.worker.start()

    def _handle_status_update(self, threat_level: str, proc_count: int, max_cpu: float):
        if not self.worker._paused and not self.active_alert_dialog:
            self.status_action.setText(f"🛡️ Shield: {threat_level} ({proc_count} procs, Max CPU: {max_cpu:.0f}%)")

    def _handle_threat_detected(self, result: DetectionResult):
        pid = result.suspect_pid
        name = result.suspect_name

        # Check if already ignored or whitelisted
        if pid in self.session_ignored_pids:
            return
        if self.db.is_whitelisted(name):
            return

        # Avoid opening multiple dialogs simultaneously
        if self.active_alert_dialog and self.active_alert_dialog.isVisible():
            return

        logger.warning("Triggering interactive alert for threat [%s] PID=%s Name=%s", result.threat_level.value, pid, name)
        self.tray_icon.setIcon(self.icon_threat)

        # Show native OS notification balloon
        self.tray_icon.showMessage(
            "🚨 Ransomware Alert!",
            f"Unusual activity detected from {name} (PID: {pid}). Action required.",
            QSystemTrayIcon.Critical,
            5000,
        )

        # Display Interactive Alert Dialog
        dialog = ThreatAlertDialog(result, on_action=self._process_user_decision)
        self.active_alert_dialog = dialog
        dialog.exec()
        self.active_alert_dialog = None
        self.tray_icon.setIcon(self.icon_safe)

    def _process_user_decision(self, action: str, result: DetectionResult):
        pid = result.suspect_pid or 0
        name = result.suspect_name or "unknown"

        if action == "terminate":
            report = self.terminator.terminate_process(pid, reason=f"User confirmed termination for {result.threat_level.value}")
            self.db.record_incident(
                threat_level=result.threat_level.value,
                confidence=result.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken=f"TERMINATED ({report.status.value})",
                features=result.features,
                details=report.details,
            )
            self.tray_icon.showMessage(
                "Process Terminated",
                f"Successfully terminated {name} (PID: {pid}). File system secured.",
                QSystemTrayIcon.Information,
                4000,
            )

        elif action == "ignore":
            if pid > 0:
                self.session_ignored_pids.add(pid)
            self.db.record_incident(
                threat_level=result.threat_level.value,
                confidence=result.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken="IGNORED_BY_USER",
                features=result.features,
                details="User selected Ignore & Allow.",
            )

        elif action == "whitelist":
            self.db.add_to_whitelist(name)
            if pid > 0:
                self.session_ignored_pids.add(pid)
            self.db.record_incident(
                threat_level=result.threat_level.value,
                confidence=result.confidence,
                suspect_pid=pid,
                suspect_name=name,
                action_taken="PERMANENTLY_WHITELISTED",
                features=result.features,
                details="User added process to permanent whitelist.",
            )
            self.tray_icon.showMessage(
                "Process Whitelisted",
                f"Added '{name}' to the permanent trusted whitelist.",
                QSystemTrayIcon.Information,
                3000,
            )

    def _trigger_test_simulation(self):
        """Simulate a controlled benign burst in test_environment to trigger prompt."""
        self.tray_icon.showMessage(
            "Test Simulation",
            "Launching safe sandbox burst in test_environment/... Alert will prompt shortly.",
            QSystemTrayIcon.Information,
            3000,
        )
        sim = SafeRansomwareSimulator(num_files=35)
        QTimer.singleShot(500, sim.run_full_simulation)

    def _show_incident_history(self):
        incidents = self.db.get_recent_incidents(limit=20)
        stats = self.db.get_stats()

        msg = f"<b>Total Threats Detected:</b> {stats['total_threats']} | <b>Terminated:</b> {stats['terminated']}<br><br>"
        if not incidents:
            msg += "<i>No incidents recorded yet. System clean.</i>"
        else:
            msg += "<table border='1' cellspacing='0' cellpadding='4' width='100%'>"
            msg += "<tr><th>Time</th><th>Threat</th><th>Process</th><th>Action</th></tr>"
            for inc in incidents:
                t_str = time.strftime("%H:%M:%S", time.localtime(inc.timestamp))
                msg += f"<tr><td>{t_str}</td><td>{inc.threat_level}</td><td>{inc.suspect_name} (PID {inc.suspect_pid})</td><td>{inc.action_taken}</td></tr>"
            msg += "</table>"

        box = QMessageBox()
        box.setWindowTitle("Incident Log & Threat Statistics")
        box.setTextFormat(Qt.RichText)
        box.setText(msg)
        box.setIcon(QMessageBox.Information)
        box.exec()

    def _toggle_protection(self):
        if self.worker._paused:
            self.worker.resume()
            self.tray_icon.setIcon(self.icon_safe)
            self.action_toggle.setText("⏸️ Pause Protection")
            self.status_action.setText("🛡️ Shield: Active (Protected)")
        else:
            self.worker.pause()
            self.tray_icon.setIcon(self.icon_paused)
            self.action_toggle.setText("▶️ Resume Protection")
            self.status_action.setText("🛡️ Shield: Paused")

    def _quit_app(self):
        logger.info("Quitting System Tray Shield.")
        self.worker.stop()
        self.tray_icon.hide()
        self.app.quit()


def launch_tray_application():
    """Launch the PySide6 system tray application."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)

    tray = SystemTrayShieldApp(app)
    logger.info("System tray application started. Entering Qt event loop.")
    return app.exec()


if __name__ == "__main__":
    sys.exit(launch_tray_application())

