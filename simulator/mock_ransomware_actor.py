"""
simulator/mock_ransomware_actor.py

A harmless standalone test process that mimics a ransomware attack burst
strictly confined inside the test_environment/ folder.

Used to test the real-time AI detection and interactive Terminate/Ignore prompt.
"""

import os
import sys
import time

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from simulator.safe_ransomware_simulator import SafeRansomwareSimulator


def main():
    pid = os.getpid()
    print("=" * 65)
    print(f"🔥 MOCK RANSOMWARE ACTOR PROCESS STARTED")
    print(f"   PID: {pid}")
    print(f"   Target Sandbox Directory: {config.TEST_ENV_DIR}")
    print("=" * 65)

    simulator = SafeRansomwareSimulator(num_files=75)

    try:
        # Step 1: Create decoy files
        print(f"[{time.strftime('%H:%M:%S')}] Step 1: Creating 75 test files in sandbox...")
        files = simulator.setup_files()
        time.sleep(0.5)

        # Step 2: Continuous attack loop with burst so user can test interactive prompt
        print(f"[{time.strftime('%H:%M:%S')}] Step 2: Initiating rapid modify & rename bursts...")
        round_count = 1
        while round_count <= 25:
            print(f"[{time.strftime('%H:%M:%S')}] Attack Round {round_count}: Overwriting and renaming files...")
            simulator.run_modify_burst(iterations=3, delay=0.005)
            simulator.run_rename_burst()
            round_count += 1
            time.sleep(1.0)

        print(f"[{time.strftime('%H:%M:%S')}] Mock attack sequence completed.")

    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%H:%M:%S')}] Mock ransomware process received interrupt.")
    finally:
        print(f"[{time.strftime('%H:%M:%S')}] Process {pid} exiting.")


if __name__ == "__main__":
    main()

