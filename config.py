"""
config.py

Central configuration for the AI-Based Ransomware Detection & Process
Termination System.

All modules should import paths/settings from here instead of
hardcoding values, so behaviour can be tuned in one place.
"""

import os

# ---------------------------------------------------------------------------
# Base project paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.join(BASE_DIR, "logs")
DATASET_DIR = os.path.join(BASE_DIR, "datasets")

# The ONLY directory the safe simulator is allowed to touch.
# This is intentionally kept separate from any real user data.
TEST_ENV_DIR = os.path.join(BASE_DIR, "test_environment")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(TEST_ENV_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(LOG_DIR, "app.log")
LOG_LEVEL = "INFO"          # DEBUG / INFO / WARNING / ERROR
LOG_MAX_BYTES = 2 * 1024 * 1024   # 2 MB per log file
LOG_BACKUP_COUNT = 5

# ---------------------------------------------------------------------------
# Process monitoring
# ---------------------------------------------------------------------------
PROCESS_POLL_INTERVAL_SECONDS = 2.0

# ---------------------------------------------------------------------------
# File-system monitoring
# ---------------------------------------------------------------------------
# During this phase of development we ONLY watch the safe test directory.
# Section 9 of the spec: do not monitor the whole C: drive yet.
DEFAULT_WATCH_DIRECTORY = TEST_ENV_DIR
FILE_EVENT_HISTORY_LIMIT = 5000   # max events kept in memory (ring buffer)
# Patterns to ignore during file monitoring to minimize noisy OS telemetry
IGNORED_FILE_PATTERNS = {".DS_Store", "desktop.ini", "Thumbs.db", ".git"}


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------
# Sliding time window used when turning raw file events into behavioral
# features (Section 15: persistence / multi-event detection, not a single
# isolated event).
FEATURE_WINDOW_SECONDS = 10

# ---------------------------------------------------------------------------
# Safe simulator (Phase 5)
# ---------------------------------------------------------------------------
SIMULATOR_DEFAULT_FILE_COUNT = 100
SIMULATOR_DEFAULT_DELAY_SECONDS = 0.02   # delay between simulated ops
SIMULATOR_RENAMED_SUFFIX = ".sim_locked"  # cosmetic only, NOT real encryption

# ---------------------------------------------------------------------------
# Machine Learning & Threat Detection (Phases 6-8)
# ---------------------------------------------------------------------------
MODEL_DIR = os.path.join(BASE_DIR, "ml", "saved_models")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(MODEL_DIR, "ransomware_detector_rf.pkl")
TRAIN_DATASET_PATH = os.path.join(DATASET_DIR, "training_dataset.csv")
TEST_DATASET_PATH = os.path.join(DATASET_DIR, "test_dataset.csv")

# Threat scoring thresholds (probability of ransomware)
THREAT_THRESHOLD_SUSPICIOUS = 0.50
THREAT_THRESHOLD_HIGH = 0.75
THREAT_THRESHOLD_CRITICAL = 0.90

