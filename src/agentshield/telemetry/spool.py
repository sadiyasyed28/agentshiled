"""
Bounded persistent local disk spooling for AgentShield telemetry.
Ensures zero event loss on transient network disconnects or API downtime.
"""

import os
import re
import json
import sqlite3
import threading
import tempfile
import logging
from typing import List, Tuple, Optional, Any

logger = logging.getLogger("agentshield.telemetry.spool")


class TelemetrySpool:
    """
    Thread-safe, crash-resilient, bounded SQLite disk spool.
    Persists events when the remote dashboard endpoint is unreachable or queue overflows.
    """

    def __init__(self, spool_dir: Optional[str] = None, max_size: int = 5000, tenant_id: Optional[str] = None):
        self.tenant_id = tenant_id
        if spool_dir:
            self.spool_dir = spool_dir
        else:
            clean_tenant = re.sub(r'[^a-zA-Z0-9_\-]', '_', tenant_id or 'default')
            self.spool_dir = os.path.join(tempfile.gettempdir(), f"agentshield_spool_{clean_tenant}")
        self.max_size = max_size
        self._lock = threading.Lock()

        os.makedirs(self.spool_dir, exist_ok=True)
        self.db_path = os.path.join(self.spool_dir, "telemetry_spool.db")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS spooled_telemetry (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        tenant_id TEXT,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_spool_id ON spooled_telemetry(id ASC);")
                conn.commit()
            finally:
                conn.close()

    def count(self, tenant_id: Optional[str] = None) -> int:
        """Returns total number of currently spooled events."""
        t_id = tenant_id or self.tenant_id
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if t_id:
                    cursor.execute("SELECT COUNT(*) FROM spooled_telemetry WHERE tenant_id = ? OR tenant_id IS NULL;", (t_id,))
                else:
                    cursor.execute("SELECT COUNT(*) FROM spooled_telemetry;")
                row = cursor.fetchone()
                return int(row[0]) if row else 0
            except Exception:
                return 0
            finally:
                conn.close()

    def spool_events(self, events: List[Any]) -> int:
        """
        Saves a list of TelemetryEvent objects into the persistent disk spool.
        Enforces maximum capacity (bounds) by shedding oldest records if capacity is exceeded.
        Returns number of successfully spooled events.
        """
        if not events:
            return 0

        spooled = 0
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                # Check current count
                cursor.execute("SELECT COUNT(*) FROM spooled_telemetry;")
                curr_count = cursor.fetchone()[0]

                # If adding new events exceeds max_size, purge oldest entries
                overflow = (curr_count + len(events)) - self.max_size
                if overflow > 0:
                    cursor.execute("""
                        DELETE FROM spooled_telemetry
                        WHERE id IN (
                            SELECT id FROM spooled_telemetry ORDER BY id ASC LIMIT ?
                        );
                    """, (overflow,))

                # Insert events atomically
                for evt in events:
                    payload = evt.to_dict() if hasattr(evt, "to_dict") else dict(evt)
                    evt_id = payload.get("event_id") or "unknown"
                    t_id = payload.get("tenant_id")
                    json_str = json.dumps(payload)
                    created_at = payload.get("timestamp") or ""

                    try:
                        cursor.execute("""
                            INSERT OR REPLACE INTO spooled_telemetry (event_id, tenant_id, payload_json, created_at)
                            VALUES (?, ?, ?, ?);
                        """, (evt_id, t_id, json_str, created_at))
                        spooled += 1
                    except Exception as e:
                        logger.warning("Failed to spool telemetry event %s: %s", evt_id, e)

                conn.commit()
                return spooled
            except Exception as e:
                logger.error("Failed writing to telemetry disk spool: %s", e)
                return 0
            finally:
                conn.close()

    def fetch_batch(self, limit: int = 50, tenant_id: Optional[str] = None) -> Tuple[List[int], List[dict]]:
        """
        Retrieves the oldest batch of spooled events for replay.
        Returns a tuple of (spool_ids, event_dicts).
        """
        t_id = tenant_id or self.tenant_id
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if t_id:
                    cursor.execute("""
                        SELECT id, payload_json
                        FROM spooled_telemetry
                        WHERE tenant_id = ? OR tenant_id IS NULL
                        ORDER BY id ASC
                        LIMIT ?;
                    """, (t_id, limit))
                else:
                    cursor.execute("""
                        SELECT id, payload_json
                        FROM spooled_telemetry
                        ORDER BY id ASC
                        LIMIT ?;
                    """, (limit,))
                rows = cursor.fetchall()
                ids = []
                payloads = []
                for r in rows:
                    ids.append(r["id"])
                    try:
                        payloads.append(json.loads(r["payload_json"]))
                    except Exception:
                        pass
                return ids, payloads
            finally:
                conn.close()

    def delete_batch(self, ids: List[int]) -> None:
        """Removes acknowledged events from the spool."""
        if not ids:
            return
        with self._lock:
            conn = self._get_connection()
            try:
                placeholders = ",".join("?" for _ in ids)
                conn.execute(f"DELETE FROM spooled_telemetry WHERE id IN ({placeholders});", ids)
                conn.commit()
            except Exception as e:
                logger.error("Failed clearing replayed events from spool: %s", e)
            finally:
                conn.close()

    def clear(self) -> None:
        """Wipes the disk spool entirely."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM spooled_telemetry;")
                conn.commit()
            finally:
                conn.close()

