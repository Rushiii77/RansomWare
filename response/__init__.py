"""
response package.

Provides automated and interactive process termination and incident response.
"""

from response.process_terminator import (
    ProcessTerminator,
    PROTECTED_SYSTEM_BINARIES,
    TerminationReport,
    TerminationStatus,
)

__all__ = [
    "ProcessTerminator",
    "PROTECTED_SYSTEM_BINARIES",
    "TerminationReport",
    "TerminationStatus",
]
