"""
Persistent storage interface and SQLite implementation for Security Events, Alerts, and Incidents.

Ensures thread-safe and multi-process-safe persistence via SQLite IMMEDIATE transactions.
All metadata is automatically scrubbed of raw secrets and credentials prior to storage.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import os
import sqlite3
import tempfile
import threading
from typing import Any, Dict, List, Optional
import uuid

from agentshield.events.models import SecurityEvent, SecurityAlert, SecurityIncident, AlertStatus, IncidentStatus, EventSeverity
from agentshield.review.store import sanitize_arguments_for_storage
from agentshield.audit.store import redact_sensitive_data

VALID_ALERT_TRANSITIONS = {
    AlertStatus.OPEN.value: {
        AlertStatus.OPEN.value,
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.INVESTIGATING.value,
        AlertStatus.RESOLVED.value,
        AlertStatus.DISMISSED.value,
    },
    AlertStatus.ACKNOWLEDGED.value: {
        AlertStatus.ACKNOWLEDGED.value,
        AlertStatus.INVESTIGATING.value,
        AlertStatus.RESOLVED.value,
        AlertStatus.DISMISSED.value,
    },
    AlertStatus.INVESTIGATING.value: {
        AlertStatus.INVESTIGATING.value,
        AlertStatus.RESOLVED.value,
        AlertStatus.DISMISSED.value,
    },
    AlertStatus.RESOLVED.value: {
        AlertStatus.RESOLVED.value,
        AlertStatus.DISMISSED.value,
    },
    AlertStatus.DISMISSED.value: {
        AlertStatus.DISMISSED.value,
    },
}

VALID_INCIDENT_TRANSITIONS = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.OPEN.value,
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.CONTAINED.value: {
        IncidentStatus.CONTAINED.value,
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.RESOLVED.value: {
        IncidentStatus.RESOLVED.value,
        IncidentStatus.CLOSED.value,
    },
    IncidentStatus.CLOSED.value: {
        IncidentStatus.CLOSED.value,
    },
}


class EventStore(ABC):
    """Abstract storage interface for Security Events, Alerts, and Incidents."""

    @abstractmethod
    def record_event(self, event: SecurityEvent) -> None:
        pass

    @abstractmethod
    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityEvent]:
        pass

    @abstractmethod
    def query_events(
        self,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        decision: Optional[str] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        pass

    @abstractmethod
    def get_recent_events_for_agent(self, agent_id: str, limit: int = 20) -> List[SecurityEvent]:
        pass

    @abstractmethod
    def create_alert(self, alert: SecurityAlert) -> None:
        pass

    @abstractmethod
    def record_alert_and_correlate(self, alert: SecurityAlert, trigger_event: SecurityEvent) -> SecurityAlert:
        """Atomically persists an alert and correlates it into an incident within a single transaction."""
        pass

    @abstractmethod
    def get_alert(self, alert_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        pass

    @abstractmethod
    def query_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        correlation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityAlert]:
        pass

    @abstractmethod
    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        actor: str,
        note: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        pass

    @abstractmethod
    def create_incident(self, incident: SecurityIncident) -> None:
        pass

    @abstractmethod
    def get_incident(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityIncident]:
        pass

    @abstractmethod
    def get_incident_by_correlation(self, correlation_id: str) -> Optional[SecurityIncident]:
        pass

    @abstractmethod
    def query_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityIncident]:
        pass

    @abstractmethod
    def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        add_alert_id: Optional[str] = None,
        increment_event_count: int = 0,
        assigned_to: Optional[str] = None,
        resolution_summary: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        pass


class SQLiteEventStore(EventStore):
    """Multi-process and thread-safe SQLite storage for security events, alerts, and incidents."""

    def __init__(self, db_path: Optional[str] = None, timeout: float = 30.0):
        self._lock = threading.Lock()
        self.timeout = timeout
        if db_path:
            self.db_path = db_path
        elif "AGENTSHIELD_EVENTS_DB" in os.environ:
            self.db_path = os.environ["AGENTSHIELD_EVENTS_DB"]
        elif os.environ.get("VERCEL"):
            self.db_path = os.path.join(tempfile.gettempdir(), "agentshield_events.db")
        else:
            self.db_path = "agentshield_events.db"
        if self.db_path != ":memory:":
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)

        self._shared_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", timeout=self.timeout, check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
            self._shared_conn.isolation_level = None
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path, timeout=self.timeout)
        conn.row_factory = sqlite3.Row
        conn.isolation_level = None
        return conn

    def _close_connection(self, conn: sqlite3.Connection) -> None:
        if self._shared_conn is not None and conn is self._shared_conn:
            return
        conn.close()

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        decision TEXT,
                        risk_score REAL NOT NULL,
                        evidence TEXT NOT NULL,
                        trace_id TEXT NOT NULL,
                        correlation_id TEXT NOT NULL,
                        metadata TEXT NOT NULL
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS security_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        agent_id TEXT NOT NULL,
                        trigger_event_id TEXT NOT NULL,
                        event_ids TEXT NOT NULL,
                        correlation_id TEXT NOT NULL,
                        incident_id TEXT,
                        acknowledged_at TEXT,
                        acknowledged_by TEXT,
                        resolved_at TEXT,
                        resolved_by TEXT,
                        resolution_note TEXT,
                        metadata TEXT NOT NULL
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id TEXT UNIQUE NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        correlation_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        alert_ids TEXT NOT NULL,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        assigned_to TEXT,
                        resolution_summary TEXT,
                        metadata TEXT NOT NULL
                    );
                """)

                # Ensure tenant_id column exists on all tables
                for tbl in ("security_events", "security_alerts", "security_incidents"):
                    cursor = conn.cursor()
                    cursor.execute(f"PRAGMA table_info({tbl});")
                    cols = [c["name"] for c in cursor.fetchall()]
                    if "tenant_id" not in cols:
                        cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';")

                # Indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_event_id ON security_events(event_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_agent_id ON security_events(agent_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_tool ON security_events(tool);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_type ON security_events(event_type);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_sev ON security_events(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_corr ON security_events(correlation_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_ts ON security_events(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evt_tenant ON security_events(tenant_id);")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_alert_id ON security_alerts(alert_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_status ON security_alerts(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_sev ON security_alerts(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_agent ON security_alerts(agent_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_corr ON security_alerts(correlation_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_inc ON security_alerts(incident_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alt_tenant ON security_alerts(tenant_id);")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_incident_id ON security_incidents(incident_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_status ON security_incidents(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_sev ON security_incidents(severity);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_corr ON security_incidents(correlation_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_tenant ON security_incidents(tenant_id);")
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def _sanitize_meta(self, meta: Any) -> Dict[str, Any]:
        cleaned = sanitize_arguments_for_storage(meta or {})
        cleaned = redact_sensitive_data(cleaned)
        return cleaned if isinstance(cleaned, dict) else {"data": cleaned}

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent:
        row_keys = row.keys()
        return SecurityEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            event_type=row["event_type"],
            severity=row["severity"],
            decision=row["decision"],
            risk_score=float(row["risk_score"]),
            evidence=json.loads(row["evidence"]),
            trace_id=row["trace_id"],
            correlation_id=row["correlation_id"],
            metadata=json.loads(row["metadata"]),
            tenant_id=row["tenant_id"] if "tenant_id" in row_keys else "default",
        )

    def _row_to_alert(self, row: sqlite3.Row) -> SecurityAlert:
        row_keys = row.keys()
        return SecurityAlert(
            alert_id=row["alert_id"],
            timestamp=row["timestamp"],
            title=row["title"],
            description=row["description"],
            alert_type=row["alert_type"],
            severity=row["severity"],
            status=row["status"],
            agent_id=row["agent_id"],
            trigger_event_id=row["trigger_event_id"],
            event_ids=json.loads(row["event_ids"]),
            correlation_id=row["correlation_id"],
            incident_id=row["incident_id"],
            acknowledged_at=row["acknowledged_at"],
            acknowledged_by=row["acknowledged_by"],
            resolved_at=row["resolved_at"],
            resolved_by=row["resolved_by"],
            resolution_note=row["resolution_note"],
            metadata=json.loads(row["metadata"]),
            tenant_id=row["tenant_id"] if "tenant_id" in row_keys else "default",
        )

    def _row_to_incident(self, row: sqlite3.Row) -> SecurityIncident:
        row_keys = row.keys()
        return SecurityIncident(
            incident_id=row["incident_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            status=row["status"],
            correlation_id=row["correlation_id"],
            agent_id=row["agent_id"],
            alert_ids=json.loads(row["alert_ids"]),
            event_count=int(row["event_count"]),
            assigned_to=row["assigned_to"],
            resolution_summary=row["resolution_summary"],
            metadata=json.loads(row["metadata"]),
            tenant_id=row["tenant_id"] if "tenant_id" in row_keys else "default",
        )

    # Event operations
    def record_event(self, event: SecurityEvent) -> None:
        sanitized_meta = self._sanitize_meta(event.metadata)
        sanitized_evidence = [redact_sensitive_data(e) for e in event.evidence]
        eff_tenant = getattr(event, "tenant_id", "default") or "default"
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO security_events (
                        event_id, timestamp, agent_id, tool, event_type,
                        severity, decision, risk_score, evidence, trace_id,
                        correlation_id, metadata, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.timestamp,
                        event.agent_id,
                        event.tool,
                        event.event_type,
                        event.severity,
                        event.decision,
                        float(event.risk_score),
                        json.dumps(sanitized_evidence),
                        event.trace_id,
                        event.correlation_id,
                        json.dumps(sanitized_meta),
                        eff_tenant,
                    ),
                )
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityEvent]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute("SELECT * FROM security_events WHERE event_id = ? AND tenant_id = ?", (event_id, tenant_id))
                else:
                    cursor.execute("SELECT * FROM security_events WHERE event_id = ?", (event_id,))
                row = cursor.fetchone()
                return self._row_to_event(row) if row else None
            finally:
                self._close_connection(conn)

    def query_events(
        self,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        decision: Optional[str] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if tenant_id is not None:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
            query += " AND agent_id = ?"
            params.append(agent_id)
        if tool:
            query += " AND tool = ?"
            params.append(tool)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if trace_id:
            query += " AND trace_id = ?"
            params.append(trace_id)
        if correlation_id:
            query += " AND correlation_id = ?"
            params.append(correlation_id)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([safe_limit, safe_offset])

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [self._row_to_event(r) for r in rows]
            finally:
                self._close_connection(conn)

    def get_recent_events_for_agent(self, agent_id: str, limit: int = 20) -> List[SecurityEvent]:
        return self.query_events(agent_id=agent_id, limit=limit)

    # Alert operations
    def create_alert(self, alert: SecurityAlert) -> None:
        sanitized_meta = self._sanitize_meta(alert.metadata)
        eff_tenant = getattr(alert, "tenant_id", "default") or "default"
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO security_alerts (
                        alert_id, timestamp, title, description, alert_type,
                        severity, status, agent_id, trigger_event_id, event_ids,
                        correlation_id, incident_id, acknowledged_at, acknowledged_by,
                        resolved_at, resolved_by, resolution_note, metadata, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.timestamp,
                        alert.title,
                        alert.description,
                        alert.alert_type,
                        alert.severity,
                        alert.status,
                        alert.agent_id,
                        alert.trigger_event_id,
                        json.dumps(alert.event_ids),
                        alert.correlation_id,
                        alert.incident_id,
                        alert.acknowledged_at,
                        alert.acknowledged_by,
                        alert.resolved_at,
                        alert.resolved_by,
                        alert.resolution_note,
                        json.dumps(sanitized_meta),
                        eff_tenant,
                    ),
                )
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def record_alert_and_correlate(self, alert: SecurityAlert, trigger_event: SecurityEvent) -> SecurityAlert:
        """Atomically stores an alert and correlates it with an existing incident or opens a new one
        within a single BEGIN IMMEDIATE transaction to prevent multi-process race conditions."""
        sanitized_meta = self._sanitize_meta(alert.metadata)
        now_ts = datetime.now(timezone.utc).isoformat()
        eff_tenant = getattr(alert, "tenant_id", None) or getattr(trigger_event, "tenant_id", "default") or "default"
        alert.tenant_id = eff_tenant
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()

                # 1. Check existing incident for this correlation_id atomically
                cursor.execute(
                    "SELECT * FROM security_incidents WHERE correlation_id = ? AND tenant_id = ? ORDER BY id DESC LIMIT 1;",
                    (alert.correlation_id, eff_tenant),
                )
                existing_inc_row = cursor.fetchone()

                if existing_inc_row:
                    inc_id = existing_inc_row["incident_id"]
                    alert.incident_id = inc_id
                    curr_alerts = json.loads(existing_inc_row["alert_ids"])
                    if alert.alert_id not in curr_alerts:
                        curr_alerts.append(alert.alert_id)
                    from agentshield.events.engine import _compare_severity
                    new_sev = _compare_severity(existing_inc_row["severity"], alert.severity)
                    new_evt_count = int(existing_inc_row["event_count"]) + 1
                    cursor.execute(
                        """
                        UPDATE security_incidents
                        SET updated_at = ?, severity = ?, alert_ids = ?, event_count = ?
                        WHERE incident_id = ?
                        """,
                        (now_ts, new_sev, json.dumps(curr_alerts), new_evt_count, inc_id),
                    )
                elif alert.severity in (EventSeverity.HIGH.value, EventSeverity.CRITICAL.value):
                    # Auto-open new incident
                    inc_id = f"inc_{uuid.uuid4().hex[:12]}"
                    alert.incident_id = inc_id
                    inc_meta = {
                        "first_alert_type": alert.alert_type,
                        "first_tool": trigger_event.tool,
                    }
                    cursor.execute(
                        """
                        INSERT INTO security_incidents (
                            incident_id, created_at, updated_at, title, description,
                            severity, status, correlation_id, agent_id, alert_ids,
                            event_count, assigned_to, resolution_summary, metadata, tenant_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            inc_id,
                            now_ts,
                            now_ts,
                            f"Incident: {alert.title}",
                            alert.description,
                            alert.severity,
                            IncidentStatus.OPEN.value,
                            alert.correlation_id,
                            alert.agent_id,
                            json.dumps([alert.alert_id]),
                            1,
                            None,
                            None,
                            json.dumps(self._sanitize_meta(inc_meta)),
                            eff_tenant,
                        ),
                    )

                # 2. Insert alert
                cursor.execute(
                    """
                    INSERT INTO security_alerts (
                        alert_id, timestamp, title, description, alert_type,
                        severity, status, agent_id, trigger_event_id, event_ids,
                        correlation_id, incident_id, acknowledged_at, acknowledged_by,
                        resolved_at, resolved_by, resolution_note, metadata, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        alert.timestamp,
                        alert.title,
                        alert.description,
                        alert.alert_type,
                        alert.severity,
                        alert.status,
                        alert.agent_id,
                        alert.trigger_event_id,
                        json.dumps(alert.event_ids),
                        alert.correlation_id,
                        alert.incident_id,
                        alert.acknowledged_at,
                        alert.acknowledged_by,
                        alert.resolved_at,
                        alert.resolved_by,
                        alert.resolution_note,
                        json.dumps(sanitized_meta),
                        eff_tenant,
                    ),
                )
                conn.commit()
                return alert
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def get_alert(self, alert_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute("SELECT * FROM security_alerts WHERE alert_id = ? AND tenant_id = ?", (alert_id, tenant_id))
                else:
                    cursor.execute("SELECT * FROM security_alerts WHERE alert_id = ?", (alert_id,))
                row = cursor.fetchone()
                return self._row_to_alert(row) if row else None
            finally:
                self._close_connection(conn)

    def query_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        alert_type: Optional[str] = None,
        correlation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityAlert]:
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if tenant_id is not None:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        if correlation_id:
            query += " AND correlation_id = ?"
            params.append(correlation_id)
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)

        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([safe_limit, safe_offset])

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [self._row_to_alert(r) for r in rows]
            finally:
                self._close_connection(conn)

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        actor: str,
        note: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute("SELECT * FROM security_alerts WHERE alert_id = ? AND tenant_id = ?", (alert_id, tenant_id))
                else:
                    cursor.execute("SELECT * FROM security_alerts WHERE alert_id = ?", (alert_id,))
                row = cursor.fetchone()
                if not row:
                    conn.commit()
                    return None

                current_status = row["status"]
                allowed_next = VALID_ALERT_TRANSITIONS.get(current_status, {current_status})
                if status not in allowed_next:
                    conn.commit()
                    raise ValueError(
                        f"Invalid alert status transition from '{current_status}' to '{status}'. Allowed transitions: {sorted(list(allowed_next))}"
                    )

                ack_at = row["acknowledged_at"]
                ack_by = row["acknowledged_by"]
                res_at = row["resolved_at"]
                res_by = row["resolved_by"]

                if status in (AlertStatus.ACKNOWLEDGED.value, AlertStatus.INVESTIGATING.value):
                    if not ack_at:
                        ack_at = now_ts
                        ack_by = actor
                elif status in (AlertStatus.RESOLVED.value, AlertStatus.DISMISSED.value):
                    res_at = now_ts
                    res_by = actor

                cursor.execute(
                    """
                    UPDATE security_alerts
                    SET status = ?, acknowledged_at = ?, acknowledged_by = ?,
                        resolved_at = ?, resolved_by = ?, resolution_note = ?
                    WHERE alert_id = ?
                    """,
                    (status, ack_at, ack_by, res_at, res_by, note, alert_id),
                )
                conn.commit()
                cursor.execute("SELECT * FROM security_alerts WHERE alert_id = ?", (alert_id,))
                updated_row = cursor.fetchone()
                return self._row_to_alert(updated_row) if updated_row else None
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    # Incident operations
    def create_incident(self, incident: SecurityIncident) -> None:
        sanitized_meta = self._sanitize_meta(incident.metadata)
        eff_tenant = getattr(incident, "tenant_id", "default") or "default"
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO security_incidents (
                        incident_id, created_at, updated_at, title, description,
                        severity, status, correlation_id, agent_id, alert_ids,
                        event_count, assigned_to, resolution_summary, metadata, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_id,
                        incident.created_at,
                        incident.updated_at,
                        incident.title,
                        incident.description,
                        incident.severity,
                        incident.status,
                        incident.correlation_id,
                        incident.agent_id,
                        json.dumps(incident.alert_ids),
                        incident.event_count,
                        incident.assigned_to,
                        incident.resolution_summary,
                        json.dumps(sanitized_meta),
                        eff_tenant,
                    ),
                )
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def get_incident(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityIncident]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ? AND tenant_id = ?", (incident_id, tenant_id))
                else:
                    cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,))
                row = cursor.fetchone()
                return self._row_to_incident(row) if row else None
            finally:
                self._close_connection(conn)

    def get_incident_by_correlation(self, correlation_id: str) -> Optional[SecurityIncident]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM security_incidents WHERE correlation_id = ? AND status != 'closed' ORDER BY id DESC LIMIT 1",
                    (correlation_id,),
                )
                row = cursor.fetchone()
                return self._row_to_incident(row) if row else None
            finally:
                self._close_connection(conn)

    def query_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        tenant_id: Optional[str] = None,
    ) -> List[SecurityIncident]:
        query = "SELECT * FROM security_incidents WHERE 1=1"
        params: List[Any] = []

        if tenant_id is not None:
            query += " AND tenant_id = ?"
            params.append(tenant_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if correlation_id:
            query += " AND correlation_id = ?"
            params.append(correlation_id)

        safe_limit = max(1, min(int(limit), 500))
        safe_offset = max(0, int(offset))
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([safe_limit, safe_offset])

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, tuple(params))
                rows = cursor.fetchall()
                return [self._row_to_incident(r) for r in rows]
            finally:
                self._close_connection(conn)

    def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        add_alert_id: Optional[str] = None,
        increment_event_count: int = 0,
        assigned_to: Optional[str] = None,
        resolution_summary: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityIncident]:
        now_ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ? AND tenant_id = ?", (incident_id, tenant_id))
                else:
                    cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,))
                row = cursor.fetchone()
                if not row:
                    conn.commit()
                    return None

                current_status = row["status"]
                if status is not None:
                    allowed_next = VALID_INCIDENT_TRANSITIONS.get(current_status, {current_status})
                    if status not in allowed_next:
                        conn.commit()
                        raise ValueError(
                            f"Invalid incident status transition from '{current_status}' to '{status}'. Allowed transitions: {sorted(list(allowed_next))}"
                        )

                current_alerts = json.loads(row["alert_ids"])
                if add_alert_id and add_alert_id not in current_alerts:
                    current_alerts.append(add_alert_id)

                new_event_count = int(row["event_count"]) + increment_event_count
                new_status = status or row["status"]
                new_severity = severity or row["severity"]
                new_assigned = assigned_to if assigned_to is not None else row["assigned_to"]
                new_resolution = resolution_summary if resolution_summary is not None else row["resolution_summary"]

                cursor.execute(
                    """
                    UPDATE security_incidents
                    SET updated_at = ?, status = ?, severity = ?, alert_ids = ?,
                        event_count = ?, assigned_to = ?, resolution_summary = ?
                    WHERE incident_id = ?
                    """,
                    (
                        now_ts,
                        new_status,
                        new_severity,
                        json.dumps(current_alerts),
                        new_event_count,
                        new_assigned,
                        new_resolution,
                        incident_id,
                    ),
                )
                conn.commit()
                cursor.execute("SELECT * FROM security_incidents WHERE incident_id = ?", (incident_id,))
                updated_row = cursor.fetchone()
                return self._row_to_incident(updated_row) if updated_row else None
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

