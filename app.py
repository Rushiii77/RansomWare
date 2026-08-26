"""
app.py

Main application entry point.

Provides:
- Complete Multi-Tab Desktop Cybersecurity Command Center GUI (PySide6)
- Background Menu Bar / System Tray Antivirus Shield
- Interactive Threat Incident Demonstration & Test Prompt
- Real-Time AI ML Behavioral Threat Detection
- Process Termination Engine & SQLite Forensic Persistence
- PDF Incident & Security Audit Report Generator
"""

import argparse
import os
import sys
import time

import config
from utils.logger import get_logger

logger = get_logger("app")


def run_gui_app():
    """Launch the primary Desktop Cybersecurity Command Center GUI."""
    from gui.main_window import launch_main_gui
    print("Launching AI Ransomware Detection & Defense Command Center...")
    launch_main_gui()


def run_tray_app():
    """Launch the background System Tray / Menu Bar Antivirus Shield."""
    from gui.tray_app import launch_tray_application
    print("Launching AI Ransomware Shield in Background (Menu Bar / System Tray)...")
    launch_tray_application()


def run_threat_demo(gui: bool = True):
    """Run full interactive user test with mock ransomware process and Terminate/Ignore prompt."""
    from simulator.demo_threat_test import run_guided_threat_demo
    run_guided_threat_demo(use_gui_popup=gui)


def run_demo():
    """Run the integrated demo testing telemetry and feature response."""
    from tests.test_integration_phase1_5 import main as run_integration
    run_integration()


def run_process_monitor():
    """Run interactive standalone Process Monitor."""
    from monitoring.process_monitor import ProcessMonitor
    monitor = ProcessMonitor(poll_interval=config.PROCESS_POLL_INTERVAL_SECONDS)
    monitor.start()
    print("Process Monitor started. Displaying top 5 CPU processes (Ctrl+C to exit)...")
    try:
        while True:
            time.sleep(2.5)
            procs = monitor.get_all_processes()
            print(f"\n--- {len(procs)} running processes observed ---")
            for p in sorted(procs, key=lambda x: x.cpu_percent, reverse=True)[:5]:
                print(f"PID: {p.pid:>6} | {p.name:<25} | CPU: {p.cpu_percent:5.1f}% | MEM: {p.memory_mb:7.1f}MB | Status: {p.status}")
    except KeyboardInterrupt:
        print("\nStopping process monitor...")
    finally:
        monitor.stop()


def run_file_monitor():
    """Run interactive standalone File Monitor."""
    from monitoring.file_monitor import FileMonitor
    fm = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)
    fm.start()
    print(f"File Monitor watching: {config.DEFAULT_WATCH_DIRECTORY}")
    print("Perform file operations inside test_environment/ (Ctrl+C to exit)...")
    try:
        while True:
            time.sleep(2.0)
            events = fm.get_recent_events(seconds=2.0)
            for e in events:
                extra = f" -> {e.dest_path}" if e.dest_path else ""
                print(f"{time.strftime('%H:%M:%S', time.localtime(e.timestamp))}  "
                      f"{e.event_type.upper():<9} {e.src_path}{extra}")
    except KeyboardInterrupt:
        print("\nStopping file monitor...")
    finally:
        fm.stop()


def run_simulator(num_files: int = 30):
    """Run the Safe Ransomware Simulator."""
    from simulator.safe_ransomware_simulator import SafeRansomwareSimulator
    sim = SafeRansomwareSimulator(num_files=num_files)
    print(f"Running safe simulation with {num_files} files inside: {sim.target_dir}")
    sim.run_full_simulation()
    print("Simulation complete. Files left in place for inspection.")
    print("Run with --cleanup to remove simulated files, or call cleanup().")


def run_cleanup():
    """Clean up simulated files from test_environment."""
    from simulator.safe_ransomware_simulator import SafeRansomwareSimulator
    sim = SafeRansomwareSimulator()
    sim.cleanup()
    print("Cleaned test_environment/ directory.")


def run_generate_dataset(samples: int = 6000):
    """Generate synthetic training and test datasets."""
    from datasets.dataset_generator import generate_and_save_datasets
    print(f"Generating {samples} labeled behavioral samples...")
    train_p, test_p = generate_and_save_datasets(samples=samples)
    print(f"Training dataset: {train_p}")
    print(f"Testing dataset:  {test_p}")


def run_train_ml():
    """Train and evaluate the Random Forest ML detection model."""
    from ml.train_model import train_and_evaluate
    print("Training AI Threat Detection Model...")
    train_and_evaluate()


def run_live_detector():
    """Run real-time AI ransomware threat detector."""
    from ml.detector import RansomwareDetector, ThreatLevel
    from monitoring.file_monitor import FileMonitor
    from monitoring.process_monitor import ProcessMonitor

    print("=" * 65)
    print("       LIVE REAL-TIME AI RANSOMWARE DETECTION ENGINE")
    print("=" * 65)
    detector = RansomwareDetector()

    p_mon = ProcessMonitor(poll_interval=2.0)
    f_mon = FileMonitor(config.DEFAULT_WATCH_DIRECTORY)

    p_mon.start()
    f_mon.start()

    print(f"Monitoring watch directory: {config.DEFAULT_WATCH_DIRECTORY}")
    print("Listening for file events and evaluating threats... (Ctrl+C to exit)\n")

    try:
        while True:
            time.sleep(2.0)
            res = detector.evaluate_live(f_mon, p_mon)
            ts = time.strftime("%H:%M:%S", time.localtime(res.evaluated_at))
            ops = res.features.get("total_operations", 0)
            ratio = res.features.get("rename_modify_ratio", 0)

            color = "\033[92m" if res.threat_level == ThreatLevel.SAFE else (
                "\033[93m" if res.threat_level == ThreatLevel.SUSPICIOUS else "\033[91m"
            )
            reset = "\033[0m"

            print(f"[{ts}] {color}{res.summary()}{reset} | Ops: {ops:>3.0f} | Ratio: {ratio:>4.2f}")
    except KeyboardInterrupt:
        print("\nStopping detector...")
    finally:
        f_mon.stop()
        p_mon.stop()


def run_benchmark():
    """Run performance benchmark on the pipeline."""
    from tests.benchmark_pipeline import run_benchmarks
    run_benchmarks()


def interactive_menu():
    """Display an interactive menu for easy navigation."""
    print("=" * 65)
    print("   AI-Based Ransomware Detection System - Interactive CLI")
    print("=" * 65)
    print("1. 🖥️  Launch Full Desktop Dashboard GUI")
    print("2. 🛡️  Launch Background System Tray / Menu Bar Antivirus Shield")
    print("3. 🚨 Run User Test Threat Incident (Mock Attack + Terminate Prompt)")
    print("4. 👁️  Live AI Threat Detector (Console Output)")
    print("5. 🧠 Train AI Detection Model (Random Forest)")
    print("6. 📊 Generate Synthetic Training Dataset")
    print("7. 🔍 Monitor Running Processes (ProcessMonitor)")
    print("8. 📁 Monitor File System Events (FileMonitor)")
    print("9. 🧪 Run Safe Ransomware Simulator (Burst Test)")
    print("10.⚡ Run Pipeline Performance Benchmark")
    print("11.🧹 Clean up test_environment files")
    print("0.  Exit")
    print("-" * 65)

    try:
        choice = input("Select an option [0-11]: ").strip()
        if choice == "1":
            run_gui_app()
        elif choice == "2":
            run_tray_app()
        elif choice == "3":
            run_threat_demo(gui=True)
        elif choice == "4":
            run_live_detector()
        elif choice == "5":
            run_train_ml()
        elif choice == "6":
            run_generate_dataset()
        elif choice == "7":
            run_process_monitor()
        elif choice == "8":
            run_file_monitor()
        elif choice == "9":
            run_simulator(num_files=30)
        elif choice == "10":
            run_benchmark()
        elif choice == "11":
            run_cleanup()
        elif choice in ("0", "q", "exit"):
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid selection.")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")


def main():
    parser = argparse.ArgumentParser(
        description="AI-Based Ransomware Detection & Process Termination System"
    )
    parser.add_argument("--gui", action="store_true", help="Launch full desktop dashboard GUI")
    parser.add_argument("--tray", action="store_true", help="Launch background system tray / menu bar shield")
    parser.add_argument("--test-threat", action="store_true", help="Run interactive threat incident user test")
    parser.add_argument("--cli", action="store_true", help="Launch interactive text menu")
    parser.add_argument("--detect", action="store_true", help="Run real-time AI threat detector in console")
    parser.add_argument("--train-ml", action="store_true", help="Train AI threat detection model")
    parser.add_argument("--generate-dataset", action="store_true", help="Generate synthetic behavioral dataset")
    parser.add_argument("--samples", type=int, default=6000, help="Number of dataset samples to generate")
    parser.add_argument("--monitor-proc", action="store_true", help="Run live process monitor")
    parser.add_argument("--monitor-fs", action="store_true", help="Run live file system monitor")
    parser.add_argument("--simulate", action="store_true", help="Run safe ransomware burst simulator")
    parser.add_argument("--files", type=int, default=30, help="Number of files for simulation (default: 30)")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--demo", action="store_true", help="Run integration demo")
    parser.add_argument("--cleanup", action="store_true", help="Clean up test_environment files")

    args = parser.parse_args()

    if args.gui:
        run_gui_app()
    elif args.tray:
        run_tray_app()
    elif args.test_threat:
        run_threat_demo(gui=True)
    elif args.cli:
        interactive_menu()
    elif args.detect:
        run_live_detector()
    elif args.train_ml:
        run_train_ml()
    elif args.generate_dataset:
        run_generate_dataset(samples=args.samples)
    elif args.demo:
        run_demo()
    elif args.monitor_proc:
        run_process_monitor()
    elif args.monitor_fs:
        run_file_monitor()
    elif args.simulate:
        run_simulator(num_files=args.files)
    elif args.benchmark:
        run_benchmark()
    elif args.cleanup:
        run_cleanup()
    else:
        # Default behavior: Launch full desktop GUI (with automatic fallback to CLI if display unavailable)
        try:
            run_gui_app()
        except Exception as e:
            logger.warning("Could not launch graphical display (%s). Falling back to interactive CLI menu.", e)
            interactive_menu()


if __name__ == "__main__":
    main()
