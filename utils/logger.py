"""
utils/logger.py

Centralized logging setup (Section 39 of the spec).

Every module in the project should obtain its logger via:

    from utils.logger import get_logger
    logger = get_logger(__name__)

so all log output is consistent and goes to both the console and the
rotating log file in /logs.
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import sys

import config

_CONFIGURED = False


def _configure_root_logger():
    global _CONFIGURED
    if _CONFIGURED:
        return

    root = logging.getLogger("ransomware_detection")
    root.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # Rotating file handler
    os.makedirs(config.LOG_DIR, exist_ok=True)
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger namespaced under 'ransomware_detection', configuring
    the shared handlers on first use.
    """
    _configure_root_logger()
    return logging.getLogger(f"ransomware_detection.{name}")
