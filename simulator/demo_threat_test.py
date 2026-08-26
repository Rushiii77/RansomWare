"""
simulator/demo_threat_test.py

Guided User Demonstration & Test Harness for Threat Incident Detection & Response.

This script demonstrates the end-to-end threat detection lifecycle:
1. Starts the background telemetry monitors (File & Process).
2. Spawns a dedicated mock ransomware process (`simulator/mock_ransomware_actor.py`).
3. Evaluates real-time behavioral features via the AI ML model.
4. Triggers the Interactive Threat Alert Prompt (GUI Popup or CLI Prompt).
5. Executes the chosen action (Terminate vs Ignore) and records the incident in SQLite.
"""

import os
import subprocess
import sys
import time

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from database.db_manager import DatabaseManager
from ml.detector import RansomwareDetector, ThreatLevel
from monitoring.file_monitor import FileMonitor
from monitoring.process_monitor import ProcessMonitor
from response.process_terminator import ProcessTerminator


def run_guided_threat_demo(use_gui_popup: bool = True):
    print("=" * 70)
    print("      AI RANSOMWARE DETECTION & RESPONSE - USER THREAT DEMO")
    print("=" * 70)
    print("This demonstration will:")
    print("  1. Launch background telemetry monitors.")
    print("  2. Spawn a separate mock ransomware process inside 'test_environment/'.")
    print("  3. Detect the behavioral anomaly in real-time with the AI ML model.")
    print("  4. Display the interactive prompt: [TERMINATE] or [IGNORE].")
    print("  5. Verify process termination and view SQLite audit records.")
    print("=" * 70)

    # Initialize components
    db = DatabaseManager()
    terminator = ProcessTerminator()
    detector = RansomwareDetector()
    file_monitor = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
    process_monitor = ProcessMonitor(poll_interval=1.5)

    print("\n[1/4] Starting background file & process telemetry...")
    process_monitor.start()
    file_monitor.start()
    time.sleep(1.0)

    print("[2/4] Spawning mock ransomware actor process...")
    actor_script = os.path.join(BASE_DIR, "simulator", "mock_ransomware_actor.py")
    actor_proc = subprocess.Popen(
        [sys.executable, actor_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    actor_pid = actor_proc.pid
    print(f"      Mock Ransomware Process spawned with PID: {actor_pid}")
    print("      Simulating attack operations in test_environment/...\n")

    # Monitor and wait for detection
    detected_result = None
    print("[3/4] AI Engine actively analyzing file modification bursts...")
    for poll in range(15):
        time.sleep(1.5)
        res = detector.evaluate_live(file_monitor, process_monitor)
        ts = time.strftime("%H:%M:%S")
        ops = res.features.get("total_operations", 0)
        ratio = res.features.get("rename_modify_ratio", 0)
        score = int(res.confidence * 100)

        print(f"[{ts}] Poll {poll+1:02d}/15: Level={res.threat_level.value:<10} Score={score:>3d}/100 | Ops={ops:>3.0f} | Ratio={ratio:.2f}")

        if res.is_ransomware:
            detected_result = res
            # Ensure target PID is mapped if detected via telemetry
            if not detected_result.suspect_pid or detected_result.suspect_pid == 0:
                detected_result.suspect_pid = actor_pid
                detected_result.suspect_name = "mock_ransomware_actor.py"
            break

    if not detected_result:
        print("\n⚠️ No threat threshold reached within timeout.")
        if actor_proc.poll() is None:
            actor_proc.kill()
        file_monitor.stop()
        process_monitor.stop()
        return

    # Check Whitelist
    if db.is_whitelisted(detected_result.suspect_name):
        print("\n" + "=" * 70)
        print(f"🛡️  WHITELIST ACTIVE: Process '{detected_result.suspect_name}' is in the permanent whitelist.")
        print(f"   AI Threat alert is suppressed and allowed without interrupting.")
        print(f"   To re-enable prompt alerts for this process, click 'Reset Whitelist' or run:")
        print(f"   python3 app.py --clear-whitelist")
        print("=" * 70 + "\n")
        if actor_proc.poll() is None:
            actor_proc.kill()
        file_monitor.stop()
        process_monitor.stop()
        return

    print("\n" + "!" * 70)
    print(f"🚨 CRITICAL THREAT DETECTED by AI Model!")
    print(f"   Offending Process: {detected_result.suspect_name} (PID: {detected_result.suspect_pid})")
    print(f"   Confidence Score:  {detected_result.confidence * 100:.1f}%")
    print(f"   Operations:        {detected_result.features.get('total_operations', 0):.0f} files touched in 10s")
    print(f"   Rename Ratio:      {detected_result.features.get('rename_modify_ratio', 0):.2f}")
    print("!" * 70 + "\n")

    # Check if GUI popup can be shown
    user_choice = None
    if use_gui_popup:
        try:
            from PySide6.QtWidgets import QApplication
            from gui.alert_dialog import ThreatAlertDialog

            app = QApplication.instance() or QApplication(sys.argv)
            print("[4/4] Opening Interactive Threat Alert Popup Window...")

            def handle_choice(action, res):
                nonlocal user_choice
                user_choice = action

            dialog = ThreatAlertDialog(detected_result, on_action=handle_choice)
            dialog.exec()

        except Exception as e:
            print(f"Note: GUI popup fallback to CLI ({e})")
            use_gui_popup = False

    # If GUI was closed or not used, fallback to interactive CLI prompt
    if not user_choice:
        print("Choose an action to respond to this threat:")
        print("  [1] 🛑 Terminate Process Immediately (Kill PID)")
        print("  [2] ⚪ Ignore & Allow Process to Continue")
        print("  [3] 🛡️ Whitelist Process Permanently")

        while True:
            try:
                choice = input("\nEnter choice [1-3] (default: 1): ").strip() or "1"
                if choice == "1":
                    user_choice = "terminate"
                    break
                elif choice == "2":
                    user_choice = "ignore"
                    break
                elif choice == "3":
                    user_choice = "whitelist"
                    break
                else:
                    print("Invalid selection. Enter 1, 2, or 3.")
            except (KeyboardInterrupt, EOFError):
                user_choice = "terminate"
                break

    # Execute User Action
    print(f"\n---> Executing User Action: '{user_choice.upper()}'")

    if user_choice == "terminate":
        rep = terminator.terminate_process(actor_pid, reason="User confirmed termination in threat demo")
        print(f"🛑 Termination Status: {rep.status.value}")
        print(f"   Details: {rep.details}")

        # Check process status
        time.sleep(0.5)
        is_alive = actor_proc.poll() is None
        print(f"   Process Alive Check: {'STILL RUNNING ❌' if is_alive else 'TERMINATED SUCCESSFULLY ✅'}")

        # Record in DB
        db.record_incident(
            threat_level=detected_result.threat_level.value,
            confidence=detected_result.confidence,
            suspect_pid=actor_pid,
            suspect_name="mock_ransomware_actor.py",
            action_taken=f"TERMINATED ({rep.status.value})",
            features=detected_result.features,
            details=rep.details,
        )

    elif user_choice == "ignore":
        print("⚪ Incident Ignored. Mock process allowed to continue.")
        db.record_incident(
            threat_level=detected_result.threat_level.value,
            confidence=detected_result.confidence,
            suspect_pid=actor_pid,
            suspect_name="mock_ransomware_actor.py",
            action_taken="IGNORED_BY_USER",
            features=detected_result.features,
            details="User ignored alert in threat demonstration.",
        )

    elif user_choice == "whitelist":
        db.add_to_whitelist("mock_ransomware_actor.py")
        print("🛡️ Added 'mock_ransomware_actor.py' to permanent whitelist.")
        db.record_incident(
            threat_level=detected_result.threat_level.value,
            confidence=detected_result.confidence,
            suspect_pid=actor_pid,
            suspect_name="mock_ransomware_actor.py",
            action_taken="PERMANENTLY_WHITELISTED",
            features=detected_result.features,
            details="User whitelisted process in demo.",
        )

    # Cleanup child process if still alive
    if actor_proc.poll() is None:
        actor_proc.terminate()
        actor_proc.wait(timeout=2.0)

    file_monitor.stop()
    process_monitor.stop()

    # Show SQLite Log
    print("\n" + "=" * 70)
    print("📜 SQLITE AUDIT TRAIL RECORD (database/incidents.db):")
    incidents = db.get_recent_incidents(limit=1)
    if incidents:
        latest = incidents[0]
        print(f"  Incident ID:   #{latest.id}")
        print(f"  Timestamp:     {time.ctime(latest.timestamp)}")
        print(f"  Threat Level:  {latest.threat_level}")
        print(f"  Confidence:    {latest.confidence * 100:.1f}%")
        print(f"  Suspect:       {latest.suspect_name} (PID {latest.suspect_pid})")
        print(f"  Action Taken:  {latest.action_taken}")
    print("=" * 70)
    print("\n✅ Threat Demonstration Complete!")


if __name__ == "__main__":
    run_guided_threat_demo(use_gui_popup=True)

