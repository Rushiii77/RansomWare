"""
simulator/safe_ransomware_simulator.py

Phase 5: Safe Ransomware-Behavior Simulator.

IMPORTANT — READ BEFORE MODIFYING THIS FILE:

This simulator exists ONLY to generate ransomware-LIKE file-system
*behavior patterns* (rapid create/modify/rename bursts) for testing the
detection pipeline. It performs:

    - plain-text file creation
    - plain-text overwrites
    - filename renames with a cosmetic suffix

It NEVER performs real encryption, does not touch any file outside a
single, explicitly validated safe directory, and has no persistence,
propagation, evasion, or credential-theft logic of any kind. Every
public method re-validates that it is operating inside the safe root
before touching disk. If that check ever fails, the method raises
SafetyViolationError and does nothing.

Do not point `target_dir` at anything other than config.TEST_ENV_DIR
(or a subdirectory of it) in production use.
"""

import os
import random
import string
import time
from typing import List

import config
from utils.logger import get_logger

logger = get_logger("simulator")


class SafetyViolationError(Exception):
    """Raised when an operation would touch a path outside the safe root."""


class SafeRansomwareSimulator:
    def __init__(self, target_dir: str = config.TEST_ENV_DIR,
                 num_files: int = config.SIMULATOR_DEFAULT_FILE_COUNT):
        self._safe_root = os.path.realpath(config.TEST_ENV_DIR)
        self.target_dir = os.path.realpath(target_dir)
        self.num_files = num_files
        self._created_files: List[str] = []

        self._enforce_safe_path(self.target_dir)
        os.makedirs(self.target_dir, exist_ok=True)

        logger.info(
            "SafeRansomwareSimulator initialized. target_dir=%s num_files=%d",
            self.target_dir, self.num_files,
        )

    # ------------------------------------------------------------------
    # Safety enforcement — called before every disk operation
    # ------------------------------------------------------------------
    def _enforce_safe_path(self, path: str):
        real_path = os.path.realpath(path)
        try:
            common = os.path.commonpath([real_path, self._safe_root])
        except ValueError:
            # Different drives on Windows, etc. -> definitely not safe.
            common = None

        if common != self._safe_root:
            logger.error(
                "SAFETY VIOLATION blocked: path %s is outside safe root %s",
                real_path, self._safe_root,
            )
            raise SafetyViolationError(
                f"Refusing to operate outside safe root '{self._safe_root}': "
                f"attempted path was '{real_path}'."
            )

    def _random_filename(self, index: int) -> str:
        suffix = "".join(random.choices(string.ascii_lowercase, k=4))
        return f"sim_file_{index:04d}_{suffix}.txt"

    # ------------------------------------------------------------------
    # Simulation stages
    # ------------------------------------------------------------------
    def setup_files(self) -> List[str]:
        """Create `num_files` harmless plain-text files in the safe dir."""
        self._enforce_safe_path(self.target_dir)
        logger.info("Simulator: creating %d test files.", self.num_files)

        created = []
        for i in range(self.num_files):
            filename = self._random_filename(i)
            path = os.path.join(self.target_dir, filename)
            self._enforce_safe_path(path)

            with open(path, "w", encoding="utf-8") as f:
                f.write("This is a harmless simulator test file.\n")
                f.write(f"index={i}\n")

            created.append(path)

        self._created_files = created
        return created

    def run_modify_burst(self, iterations: int = 3,
                          delay: float = config.SIMULATOR_DEFAULT_DELAY_SECONDS):
        """Rapidly rewrite the content of each simulated file, `iterations`
        times, to mimic a burst of modification activity."""
        if not self._created_files:
            logger.warning("run_modify_burst called with no files set up yet; call setup_files() first.")
            return

        logger.info("Simulator: running modify burst (%d iterations).", iterations)
        for round_num in range(iterations):
            for path in self._created_files:
                self._enforce_safe_path(path)
                if not os.path.exists(path):
                    continue
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"modified round={round_num} ts={time.time()}\n")
                time.sleep(delay)

    def run_rename_burst(self, suffix: str = config.SIMULATOR_RENAMED_SUFFIX):
        """Rename every simulated file, appending a cosmetic suffix.
        This is NOT encryption — file contents are untouched, only the
        filename changes, to mimic ransomware-style rename patterns."""
        if not self._created_files:
            logger.warning("run_rename_burst called with no files set up yet; call setup_files() first.")
            return

        logger.info("Simulator: running rename burst.")
        renamed = []
        for path in self._created_files:
            self._enforce_safe_path(path)
            if not os.path.exists(path):
                continue
            new_path = path + suffix
            self._enforce_safe_path(new_path)
            os.rename(path, new_path)
            renamed.append(new_path)
            time.sleep(config.SIMULATOR_DEFAULT_DELAY_SECONDS)

        self._created_files = renamed

    def run_full_simulation(self):
        """Convenience method: create -> modify burst -> rename burst."""
        logger.info("Simulator: running full simulation sequence.")
        self.setup_files()
        time.sleep(0.5)
        self.run_modify_burst(iterations=3)
        time.sleep(0.5)
        self.run_rename_burst()
        logger.info("Simulator: full simulation sequence complete.")

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup(self):
        """Delete every file this simulator instance created/renamed.
        Restricted to the safe root like every other operation here."""
        logger.info("Simulator: cleaning up %d files.", len(self._created_files))
        for path in list(self._created_files):
            self._enforce_safe_path(path)
            if os.path.exists(path):
                os.remove(path)
        self._created_files.clear()


# ---------------------------------------------------------------------------
# Manual smoke test: `python -m simulator.safe_ransomware_simulator`
# Run this alongside file_monitor.py / feature_extractor.py in another
# terminal to see the detection pipeline react to the simulated burst.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sim = SafeRansomwareSimulator(num_files=30)
    print(f"Running safe simulation inside: {sim.target_dir}")
    sim.run_full_simulation()
    print("Simulation complete. Files left in place for inspection.")
    print("Call cleanup() manually or delete test_environment/ contents when done.")
