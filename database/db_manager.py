"""
database/db_manager.py

Phase 12: SQLite Incident & Whitelist Database Persistence.

Persists detected threat events, user response decisions, and application whitelists.
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import config
from utils.logger import get_logger

logger = get_logger("db_manager")

DEFAULT_DB_PATH = os.path.join(config.BASE_DIR, "database", "incidents.db")


@dataclass
class IncidentRecord:
    id: int
    timestamp: float
    threat_level: str
    confidence: float
    suspect_pid: Optional[int]
    suspect_name: Optional[str]
    action_taken: str
    features: Dict[str, float]
    details: str


class DatabaseManager:
    """Thread-safe SQLite manager for threat incidents and whitelists."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    threat_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    suspect_pid INTEGER,
                    suspect_name TEXT,
                    action_taken TEXT NOT NULL,
                    features_json TEXT,
                    details TEXT
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    path TEXT,
                    created_at REAL NOT NULL
                )
            """)
            conn.commit()
            logger.debug("Database initialized at %s", self.db_path)

    def record_incident(
        self,
        threat_level: str,
        confidence: float,
        suspect_pid: Optional[int],
        suspect_name: Optional[str],
        action_taken: str,
        features: Optional[Dict[str, float]] = None,
        details: str = "",
    ) -> int:
        """Insert a new threat incident record."""
        feat_str = json.dumps(features or {})
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents (
                    timestamp, threat_level, confidence, suspect_pid, suspect_name, action_taken, features_json, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (now, threat_level, confidence, suspect_pid, suspect_name, action_taken, feat_str, details))
            conn.commit()
            incident_id = cursor.lastrowid
            logger.info("Recorded incident #%d: [%s] Suspect=%s (Action: %s)", incident_id, threat_level, suspect_name, action_taken)
            return incident_id

    def get_recent_incidents(self, limit: int = 50) -> List[IncidentRecord]:
        """Retrieve recent incident records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, threat_level, confidence, suspect_pid, suspect_name, action_taken, features_json, details
                FROM incidents
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

            records = []
            for r in rows:
                try:
                    feat = json.loads(r["features_json"]) if r["features_json"] else {}
                except Exception:
                    feat = {}
                records.append(IncidentRecord(
                    id=r["id"],
                    timestamp=r["timestamp"],
                    threat_level=r["threat_level"],
                    confidence=r["confidence"],
                    suspect_pid=r["suspect_pid"],
                    suspect_name=r["suspect_name"],
                    action_taken=r["action_taken"],
                    features=feat,
                    details=r["details"] or "",
                ))
            return records

    def add_to_whitelist(self, name: str, path: Optional[str] = None) -> bool:
        """Add a process name to the permanent whitelist."""
        clean_name = name.strip().lower()
        now = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO whitelist (name, path, created_at)
                    VALUES (?, ?, ?)
                """, (clean_name, path, now))
                conn.commit()
                logger.info("Added '%s' to whitelist.", clean_name)
                return True
        except Exception as e:
            logger.error("Error adding to whitelist: %s", e)
            return False

    def remove_from_whitelist(self, name: str) -> bool:
        """Remove a process name from the permanent whitelist."""
        clean_name = name.strip().lower()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM whitelist WHERE name = ?", (clean_name,))
                conn.commit()
                logger.info("Removed '%s' from whitelist.", clean_name)
                return True
        except Exception as e:
            logger.error("Error removing from whitelist: %s", e)
            return False

    def clear_whitelist(self) -> int:
        """Clear all entries from whitelist table."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM whitelist")
                deleted = cursor.rowcount
                conn.commit()
                logger.info("Cleared entire whitelist (%d entries removed).", deleted)
                return deleted
        except Exception as e:
            logger.error("Error clearing whitelist: %s", e)
            return 0

    def clear_all_incidents(self) -> int:
        """Clear all incident records from database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM incidents")
                deleted = cursor.rowcount
                conn.commit()
                logger.info("Cleared all incidents (%d records removed).", deleted)
                return deleted
        except Exception as e:
            logger.error("Error clearing incidents: %s", e)
            return 0

    def reset_database_to_default(self):
        """Reset whitelist, incidents, and detections back to clean default factory state."""
        self.clear_whitelist()
        self.clear_all_incidents()
        logger.info("Database reset to factory default clean state.")

    def is_whitelisted(self, name: Optional[str]) -> bool:
        """Check if process name is whitelisted."""
        if not name:
            return False
        clean_name = name.strip().lower()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM whitelist WHERE name = ?", (clean_name,))
            return cursor.fetchone() is not None

    def get_whitelist(self) -> List[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM whitelist ORDER BY name ASC")
            return [r["name"] for r in cursor.fetchall()]

    def get_stats(self) -> Dict[str, int]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM incidents")
            total = cursor.fetchone()["total"]
            cursor.execute("SELECT COUNT(*) as terminated FROM incidents WHERE action_taken LIKE '%TERMINATED%'")
            term = cursor.fetchone()["terminated"]
            cursor.execute("SELECT COUNT(*) as ignored FROM incidents WHERE action_taken LIKE '%IGNORED%'")
            ign = cursor.fetchone()["ignored"]
            return {"total_threats": total, "terminated": term, "ignored": ign}


