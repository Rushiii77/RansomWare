"""
response/process_terminator.py

Phase 11: Process Termination & Automated Threat Response Engine.

Provides safe, controlled termination of confirmed malicious processes.
Includes critical system process whitelisting to prevent accidental termination
of OS system binaries (Section 29/38 of the spec).
"""

import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set

import psutil

from utils.logger import get_logger

logger = get_logger("process_terminator")


class TerminationStatus(str, Enum):
    TERMINATED = "TERMINATED"
    KILLED_FORCEFULLY = "KILLED_FORCEFULLY"
    PROTECTED_SYSTEM_PROCESS = "PROTECTED_SYSTEM_PROCESS"
    PROCESS_NOT_FOUND = "PROCESS_NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    FAILED = "FAILED"


@dataclass
class TerminationReport:
    pid: int
    process_name: str
    status: TerminationStatus
    exe_path: Optional[str] = None
    reason: str = ""
    timestamp: float = 0.0
    details: str = ""


# System critical process basenames that can NEVER be terminated
PROTECTED_SYSTEM_BINARIES: Set[str] = {
    # Unix / macOS
    "kernel_task",
    "launchd",
    "system",
    "systemd",
    "init",
    "finder",
    "dock",
    "windowserver",
    "loginwindow",
    "syslogd",
    "distnoted",
    "coreauthd",
    # Windows
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "explorer.exe",
    "taskmgr.exe",
}


class ProcessTerminator:
    """Safely terminates offending processes with validation and logging."""

    def __init__(self, protected_binaries: Optional[Set[str]] = None):
        self.protected_binaries = (
            {b.lower() for b in protected_binaries} if protected_binaries else PROTECTED_SYSTEM_BINARIES
        )

    def is_protected(self, pid: int, name: Optional[str] = None) -> bool:
        """Check if process is a critical system service or PID <= 1."""
        if pid <= 1:
            return True
        if name and name.lower().strip() in self.protected_binaries:
            return True
        return False

    def terminate_process(
        self,
        pid: int,
        reason: str = "Suspected ransomware attack",
        force_timeout: float = 3.0,
    ) -> TerminationReport:
        """
        Attempt graceful termination (SIGTERM), falling back to SIGKILL if not responsive.
        """
        now = time.time()
        logger.info("Initiating process termination request for PID=%d. Reason: %s", pid, reason)

        # Check PID 0/1 guard
        if pid <= 1:
            logger.error("Refusing to terminate root system PID %d.", pid)
            return TerminationReport(
                pid=pid,
                process_name="system_root",
                status=TerminationStatus.PROTECTED_SYSTEM_PROCESS,
                reason=reason,
                timestamp=now,
                details="PID <= 1 is protected.",
            )

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = None
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Safety check against critical OS binaries
            if self.is_protected(pid, name):
                logger.error("Refusing to terminate protected system process: %s (PID %d)", name, pid)
                return TerminationReport(
                    pid=pid,
                    process_name=name,
                    status=TerminationStatus.PROTECTED_SYSTEM_PROCESS,
                    exe_path=exe,
                    reason=reason,
                    timestamp=now,
                    details=f"Process '{name}' is in the critical system whitelist.",
                )

            # Attempt graceful termination
            proc.terminate()
            try:
                proc.wait(timeout=force_timeout)
                logger.info("Process %s (PID %d) successfully terminated gracefully.", name, pid)
                return TerminationReport(
                    pid=pid,
                    process_name=name,
                    status=TerminationStatus.TERMINATED,
                    exe_path=exe,
                    reason=reason,
                    timestamp=now,
                    details="Terminated via SIGTERM.",
                )
            except psutil.TimeoutExpired:
                # Forceful kill if still active
                logger.warning("Process %s (PID %d) did not terminate in time. Killing forcefully...", name, pid)
                proc.kill()
                proc.wait(timeout=2.0)
                logger.info("Process %s (PID %d) killed forcefully.", name, pid)
                return TerminationReport(
                    pid=pid,
                    process_name=name,
                    status=TerminationStatus.KILLED_FORCEFULLY,
                    exe_path=exe,
                    reason=reason,
                    timestamp=now,
                    details="Killed forcefully via SIGKILL after timeout.",
                )

        except psutil.NoSuchProcess:
            logger.warning("Process PID %d not found (may have already exited).", pid)
            return TerminationReport(
                pid=pid,
                process_name="unknown",
                status=TerminationStatus.PROCESS_NOT_FOUND,
                reason=reason,
                timestamp=now,
                details="Process not found.",
            )
        except psutil.AccessDenied as e:
            logger.error("Access denied terminating PID %d: %s", pid, e)
            return TerminationReport(
                pid=pid,
                process_name="unknown",
                status=TerminationStatus.ACCESS_DENIED,
                reason=reason,
                timestamp=now,
                details=f"Access denied: {e}",
            )
        except Exception as e:
            logger.exception("Unexpected error terminating PID %d.", pid)
            return TerminationReport(
                pid=pid,
                process_name="unknown",
                status=TerminationStatus.FAILED,
                reason=reason,
                timestamp=now,
                details=str(e),
            )

