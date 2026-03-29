#!/usr/bin/env python3
"""
XDR Event Store — Persistent event logging with SQLite + disguised backup file.
- SQLite DB for fast queries (telemetry.db)
- Append-only disguised file for integrity backup (font_metrics.dat)
"""

import os
import json
import sqlite3
import logging
import time
import threading
from datetime import datetime
from pathlib import Path

DB_DIR = Path("/opt/xdr/data")
DB_PATH = DB_DIR / "telemetry.db"

# Disguised log file — looks like a font cache to hide from attackers
BACKUP_DIR = Path("/opt/xdr/.cache")
BACKUP_PATH = BACKUP_DIR / "font_metrics.dat"

# Retention
MAX_EVENTS = 500_000       # ~200MB at 400 bytes/event
CLEANUP_INTERVAL = 3600    # 1 hour


class EventStore:
    """Thread-safe persistent event store."""

    def __init__(self):
        self._lock = threading.Lock()
        self._write_count = 0

        # Create directories
        DB_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize SQLite
        self._init_db()

        # Start cleanup thread
        self._stop = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="event-cleanup")
        self._cleanup_thread.start()

    def _init_db(self):
        """Create DB and tables if needed."""
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT,
                action TEXT,
                reason TEXT,
                detail TEXT,
                alert_level INTEGER DEFAULT 0,
                pid INTEGER,
                comm TEXT,
                raw JSON
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_level ON events(alert_level)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)
        """)
        conn.commit()
        conn.close()

    def store(self, event: dict):
        """Store event to SQLite + disguised backup file."""
        try:
            ts = event.get("_time", datetime.now().isoformat())
            source = event.get("source", "")
            action = event.get("action", "")
            reason = event.get("reason", "")
            detail = str(event.get("detail", ""))[:500]
            level = event.get("alert_level", 0)
            pid = event.get("pid", 0)
            comm = event.get("comm", "")
            raw = json.dumps(event, default=str)

            # SQLite insert
            with self._lock:
                conn = sqlite3.connect(str(DB_PATH), timeout=5)
                conn.execute(
                    "INSERT INTO events (timestamp, source, action, reason, detail, "
                    "alert_level, pid, comm, raw) VALUES (?,?,?,?,?,?,?,?,?)",
                    (ts, source, action, reason, detail, level, pid, comm, raw)
                )
                conn.commit()
                conn.close()

            # Disguised backup: append JSON line
            with open(BACKUP_PATH, "a") as f:
                f.write(raw + "\n")

            self._write_count += 1
        except Exception as e:
            logging.debug(f"EventStore write error: {e}")

    def query(self, limit=100, offset=0, level_min=None,
              source=None, since=None, until=None, search=None):
        """Query events with filters."""
        conditions = []
        params = []

        if level_min is not None:
            conditions.append("alert_level >= ?")
            params.append(level_min)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        if search:
            conditions.append("(detail LIKE ? OR reason LIKE ? OR comm LIKE ?)")
            params.extend([f"%{search}%"] * 3)

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT id, timestamp, source, action, reason, detail, alert_level, pid, comm FROM events WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=5)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            logging.error(f"EventStore query error: {e}")
            return []

    def count(self, level_min=None, source=None):
        """Count total events with optional filters."""
        conditions = []
        params = []
        if level_min is not None:
            conditions.append("alert_level >= ?")
            params.append(level_min)
        if source:
            conditions.append("source = ?")
            params.append(source)
        where = " AND ".join(conditions) if conditions else "1=1"

        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=5)
            result = conn.execute(
                f"SELECT COUNT(*) FROM events WHERE {where}", params
            ).fetchone()[0]
            conn.close()
            return result
        except Exception:
            return 0

    def _cleanup_loop(self):
        """Periodically trim old events."""
        while not self._stop.wait(CLEANUP_INTERVAL):
            try:
                conn = sqlite3.connect(str(DB_PATH), timeout=10)
                count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                if count > MAX_EVENTS:
                    delete_count = count - MAX_EVENTS
                    conn.execute(
                        f"DELETE FROM events WHERE id IN "
                        f"(SELECT id FROM events ORDER BY id ASC LIMIT ?)",
                        (delete_count,)
                    )
                    conn.commit()
                    logging.info(f"EventStore: trimmed {delete_count} old events")
                conn.close()
            except Exception as e:
                logging.debug(f"EventStore cleanup error: {e}")

    def stop(self):
        self._stop.set()


# Singleton instance
_store = None


def get_event_store() -> EventStore:
    global _store
    if _store is None:
        _store = EventStore()
    return _store
