"""
database package.

Provides SQLite persistence for ransomware incidents, audit logs, and whitelists.
"""

from database.db_manager import DatabaseManager, IncidentRecord

__all__ = ["DatabaseManager", "IncidentRecord"]
