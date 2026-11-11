"""
PostgreSQL Event Store for AgentShield.

Manages persistent storage for Security Events, Alerts, and Incidents with
atomic transactional correlation and multi-instance concurrency safety.
Supports configurable table prefixes for complete simulator isolation.
"""

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

from agentshield.events.models import (
    AlertStatus,
    EventSeverity,
    EventType,
    IncidentStatus,
    SecurityAlert,
    SecurityEvent,
    SecurityIncident,
)
from agentshield.events.store import EventStore
from agentshield.storage.connection import PostgresConnectionManager

logger = logging.getLogger("agentshield.storage.events")


class PostgresEventStore(EventStore):
    """PostgreSQL implementation of EventStore."""

    def __init__(
        self,
        dsn: str,
        table_prefix: str = "",
        connection_manager: Optional[PostgresConnectionManager] = None,
    ):
        self.table_prefix = table_prefix
        self.events_table = f"{table_prefix}security_events"
        self.alerts_table = f"{table_prefix}security_alerts"
        self.incidents_table = f"{table_prefix}security_incidents"
        self.connection_manager = connection_manager or PostgresConnectionManager(dsn=dsn)
        self.init_db()

    def init_db(self) -> None:
        """Initializes security events, alerts, and incidents tables."""
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.events_table} (
                    event_id VARCHAR(64) PRIMARY KEY,
                    tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
                    timestamp TEXT NOT NULL,
                    agent_id VARCHAR(128) NOT NULL,
                    tool VARCHAR(128) NOT NULL,
                    event_type VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    decision VARCHAR(32),
                    risk_score DOUBLE PRECISION NOT NULL,
                    evidence TEXT NOT NULL,
                    trace_id VARCHAR(64) NOT NULL,
                    correlation_id VARCHAR(64) NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                );
            """)
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.events_table}_agent ON {self.events_table}(agent_id);")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.events_table}_corr ON {self.events_table}(correlation_id);")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.events_table}_tenant ON {self.events_table}(tenant_id);")

            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.alerts_table} (
                    alert_id VARCHAR(64) PRIMARY KEY,
                    tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
                    timestamp TEXT NOT NULL,
                    title VARCHAR(256) NOT NULL,
                    description TEXT NOT NULL,
                    alert_type VARCHAR(64) NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    agent_id VARCHAR(128) NOT NULL,
                    trigger_event_id VARCHAR(64),
                    event_ids TEXT NOT NULL,
                    correlation_id VARCHAR(64),
                    incident_id VARCHAR(64),
                    acknowledged_at TEXT,
                    acknowledged_by VARCHAR(128),
                    resolved_at TEXT,
                    resolved_by VARCHAR(128),
                    resolution_note TEXT,
                    metadata TEXT NOT NULL DEFAULT '{{}}',
                    created_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL
                );
            """)
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.alerts_table}_tenant ON {self.alerts_table}(tenant_id);")

            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.incidents_table} (
                    incident_id VARCHAR(64) PRIMARY KEY,
                    tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    title VARCHAR(256) NOT NULL,
                    description TEXT NOT NULL,
                    severity VARCHAR(32) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    agent_id VARCHAR(128),
                    correlation_id VARCHAR(64),
                    alert_ids TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    assigned_to VARCHAR(128),
                    resolution_summary TEXT,
                    metadata TEXT NOT NULL DEFAULT '{{}}'
                );
            """)
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.incidents_table}_tenant ON {self.incidents_table}(tenant_id);")

    def record_event(self, event: SecurityEvent) -> None:
        now = time.time()
        tenant = event.tenant_id or "default"
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO {self.events_table} (
                    event_id, tenant_id, timestamp, agent_id, tool, event_type, severity,
                    decision, risk_score, evidence, trace_id, correlation_id,
                    metadata, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                event.event_id,
                tenant,
                event.timestamp,
                event.agent_id,
                event.tool,
                event.event_type,
                event.severity,
                event.decision,
                float(event.risk_score),
                json.dumps(event.evidence),
                event.trace_id,
                event.correlation_id,
                json.dumps(event.metadata),
                now,
            ))

    def _row_to_event(self, row_dict: Dict[str, Any]) -> SecurityEvent:
        return SecurityEvent(
            event_id=row_dict["event_id"],
            timestamp=row_dict["timestamp"],
            agent_id=row_dict["agent_id"],
            tool=row_dict["tool"],
            event_type=row_dict["event_type"],
            severity=row_dict["severity"],
            decision=row_dict.get("decision"),
            risk_score=row_dict["risk_score"],
            evidence=json.loads(row_dict["evidence"]),
            trace_id=row_dict["trace_id"],
            correlation_id=row_dict["correlation_id"],
            metadata=json.loads(row_dict["metadata"]),
            tenant_id=row_dict.get("tenant_id") or "default",
        )

    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityEvent]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id:
                cursor.execute(f"SELECT * FROM {self.events_table} WHERE event_id = %s AND tenant_id = %s;", (event_id, tenant_id))
            else:
                cursor.execute(f"SELECT * FROM {self.events_table} WHERE event_id = %s;", (event_id,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_event(dict(zip(col_names, row)))

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
        conditions: List[str] = []
        params: List[Any] = []

        if tenant_id:
            conditions.append("tenant_id = %s")
            params.append(tenant_id)
        if agent_id:
            conditions.append("agent_id = %s")
            params.append(agent_id)
        if tool:
            conditions.append("tool = %s")
            params.append(tool)
        if event_type:
            conditions.append("event_type = %s")
            params.append(event_type)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if decision:
            conditions.append("decision = %s")
            params.append(decision)
        if trace_id:
            conditions.append("trace_id = %s")
            params.append(trace_id)
        if correlation_id:
            conditions.append("correlation_id = %s")
            params.append(correlation_id)
        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query_sql = f"""
            SELECT * FROM {self.events_table}
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s;
        """
        params.extend([limit, offset])

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, tuple(params))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            return [self._row_to_event(dict(zip(col_names, r))) for r in cursor.fetchall()]

    def get_recent_events_for_agent(self, agent_id: str, limit: int = 20) -> List[SecurityEvent]:
        return self.query_events(agent_id=agent_id, limit=limit)

    def create_alert(self, alert: SecurityAlert) -> None:
        now = time.time()
        tenant = alert.tenant_id or "default"
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO {self.alerts_table} (
                    alert_id, tenant_id, timestamp, title, description, alert_type, severity,
                    status, agent_id, trigger_event_id, event_ids, correlation_id,
                    incident_id, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                alert.alert_id,
                tenant,
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
                now,
                now,
            ))

    def _row_to_alert(self, row_dict: Dict[str, Any]) -> SecurityAlert:
        raw_meta = row_dict.get("metadata")
        meta = json.loads(raw_meta) if raw_meta and isinstance(raw_meta, str) else {}
        return SecurityAlert(
            alert_id=row_dict["alert_id"],
            timestamp=row_dict["timestamp"],
            title=row_dict["title"],
            description=row_dict["description"],
            alert_type=row_dict["alert_type"],
            severity=row_dict["severity"],
            status=row_dict["status"],
            agent_id=row_dict["agent_id"],
            trigger_event_id=row_dict.get("trigger_event_id", ""),
            event_ids=json.loads(row_dict.get("event_ids") or "[]"),
            correlation_id=row_dict.get("correlation_id", ""),
            incident_id=row_dict.get("incident_id"),
            acknowledged_at=row_dict.get("acknowledged_at"),
            acknowledged_by=row_dict.get("acknowledged_by"),
            resolved_at=row_dict.get("resolved_at"),
            resolved_by=row_dict.get("resolved_by"),
            resolution_note=row_dict.get("resolution_note") or row_dict.get("resolution_notes"),
            metadata=meta,
            tenant_id=row_dict.get("tenant_id") or "default",
        )

    def get_alert(self, alert_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id:
                cursor.execute(f"SELECT * FROM {self.alerts_table} WHERE alert_id = %s AND tenant_id = %s;", (alert_id, tenant_id))
            else:
                cursor.execute(f"SELECT * FROM {self.alerts_table} WHERE alert_id = %s;", (alert_id,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_alert(dict(zip(col_names, row)))

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
        conditions: List[str] = []
        params: List[Any] = []

        if tenant_id:
            conditions.append("tenant_id = %s")
            params.append(tenant_id)
        if status:
            conditions.append("status = %s")
            params.append(status)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if agent_id:
            conditions.append("agent_id = %s")
            params.append(agent_id)
        if alert_type:
            conditions.append("alert_type = %s")
            params.append(alert_type)
        if correlation_id:
            conditions.append("correlation_id = %s")
            params.append(correlation_id)
        if incident_id:
            conditions.append("incident_id = %s")
            params.append(incident_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query_sql = f"""
            SELECT * FROM {self.alerts_table}
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s;
        """
        params.extend([limit, offset])

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, tuple(params))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            return [self._row_to_alert(dict(zip(col_names, r))) for r in cursor.fetchall()]

    def update_alert_status(
        self,
        alert_id: str,
        status: str,
        actor: str,
        note: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[SecurityAlert]:
        now_ts = datetime.now(timezone.utc).isoformat()
        now_epoch = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            tenant_cond = "AND tenant_id = %s" if tenant_id else ""
            extra_params = (tenant_id,) if tenant_id else ()
            if status == AlertStatus.ACKNOWLEDGED.value:
                cursor.execute(f"""
                    UPDATE {self.alerts_table}
                    SET status = %s, acknowledged_at = %s, acknowledged_by = %s, updated_at = %s
                    WHERE alert_id = %s {tenant_cond};
                """, (status, now_ts, actor, now_epoch, alert_id) + extra_params)
            elif status == AlertStatus.RESOLVED.value:
                cursor.execute(f"""
                    UPDATE {self.alerts_table}
                    SET status = %s, resolved_at = %s, resolved_by = %s, resolution_notes = %s, updated_at = %s
                    WHERE alert_id = %s {tenant_cond};
                """, (status, now_ts, actor, note, now_epoch, alert_id) + extra_params)
            else:
                cursor.execute(f"""
                    UPDATE {self.alerts_table}
                    SET status = %s, updated_at = %s
                    WHERE alert_id = %s {tenant_cond};
                """, (status, now_epoch, alert_id) + extra_params)
        return self.get_alert(alert_id, tenant_id=tenant_id)

    def create_incident(self, incident: SecurityIncident) -> None:
        tenant = incident.tenant_id or "default"
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO {self.incidents_table} (
                    incident_id, tenant_id, created_at, updated_at, title, description,
                    severity, status, agent_id, correlation_id, alert_ids,
                    event_count, assigned_to, resolution_summary, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                incident.incident_id,
                tenant,
                incident.created_at,
                incident.updated_at,
                incident.title,
                incident.description,
                incident.severity,
                incident.status,
                incident.agent_id,
                incident.correlation_id,
                json.dumps(incident.alert_ids),
                incident.event_count,
                incident.assigned_to,
                incident.resolution_summary,
                json.dumps(incident.metadata or {}),
            ))

    def _row_to_incident(self, row_dict: Dict[str, Any]) -> SecurityIncident:
        raw_meta = row_dict.get("metadata")
        meta = json.loads(raw_meta) if raw_meta and isinstance(raw_meta, str) else {}
        return SecurityIncident(
            incident_id=row_dict["incident_id"],
            created_at=row_dict["created_at"],
            updated_at=row_dict["updated_at"],
            title=row_dict["title"],
            description=row_dict["description"],
            severity=row_dict["severity"],
            status=row_dict["status"],
            agent_id=row_dict.get("agent_id") or "unknown",
            correlation_id=row_dict.get("correlation_id") or "",
            alert_ids=json.loads(row_dict.get("alert_ids") or "[]"),
            event_count=int(row_dict.get("event_count") or 0),
            assigned_to=row_dict.get("assigned_to"),
            resolution_summary=row_dict.get("resolution_summary"),
            metadata=meta,
            tenant_id=row_dict.get("tenant_id") or "default",
        )

    def get_incident(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityIncident]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id:
                cursor.execute(f"SELECT * FROM {self.incidents_table} WHERE incident_id = %s AND tenant_id = %s;", (incident_id, tenant_id))
            else:
                cursor.execute(f"SELECT * FROM {self.incidents_table} WHERE incident_id = %s;", (incident_id,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_incident(dict(zip(col_names, row)))

    def get_incident_by_correlation(self, correlation_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityIncident]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id:
                cursor.execute(f"SELECT * FROM {self.incidents_table} WHERE correlation_id = %s AND tenant_id = %s;", (correlation_id, tenant_id))
            else:
                cursor.execute(f"SELECT * FROM {self.incidents_table} WHERE correlation_id = %s;", (correlation_id,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_incident(dict(zip(col_names, row)))

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
        conditions: List[str] = []
        params: List[Any] = []

        if tenant_id:
            conditions.append("tenant_id = %s")
            params.append(tenant_id)
        if status:
            conditions.append("status = %s")
            params.append(status)
        if severity:
            conditions.append("severity = %s")
            params.append(severity)
        if agent_id:
            conditions.append("agent_id = %s")
            params.append(agent_id)
        if correlation_id:
            conditions.append("correlation_id = %s")
            params.append(correlation_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query_sql = f"""
            SELECT * FROM {self.incidents_table}
            {where_clause}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s;
        """
        params.extend([limit, offset])

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, tuple(params))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            return [self._row_to_incident(dict(zip(col_names, r))) for r in cursor.fetchall()]

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
        current = self.get_incident(incident_id, tenant_id=tenant_id)
        if not current:
            return None

        alert_ids = list(current.alert_ids)
        if add_alert_id and add_alert_id not in alert_ids:
            alert_ids.append(add_alert_id)
        new_event_count = current.event_count + increment_event_count
        new_status = status or current.status
        new_severity = severity or current.severity
        new_assigned = assigned_to if assigned_to is not None else current.assigned_to
        new_resolution = resolution_summary if resolution_summary is not None else current.resolution_summary

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            tenant_cond = "AND tenant_id = %s" if tenant_id else ""
            extra_params = (tenant_id,) if tenant_id else ()
            cursor.execute(f"""
                UPDATE {self.incidents_table}
                SET status = %s, severity = %s, alert_ids = %s, event_count = %s,
                    assigned_to = %s, resolution_summary = %s, updated_at = %s
                WHERE incident_id = %s {tenant_cond};
            """, (
                new_status,
                new_severity,
                json.dumps(alert_ids),
                new_event_count,
                new_assigned,
                new_resolution,
                now_ts,
                incident_id,
            ) + extra_params)
        return self.get_incident(incident_id, tenant_id=tenant_id)

    def record_alert_and_correlate(self, alert: SecurityAlert, trigger_event: SecurityEvent) -> SecurityAlert:
        """Atomically persists alert and correlates with an incident in a single transaction."""
        now = time.time()
        now_ts = datetime.now(timezone.utc).isoformat()
        tenant = alert.tenant_id or trigger_event.tenant_id or "default"
        alert.tenant_id = tenant
        trigger_event.tenant_id = tenant

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            # 1. Correlate with existing incident by correlation_id AND tenant_id
            cursor.execute(f"""
                SELECT incident_id, alert_ids, event_count
                FROM {self.incidents_table}
                WHERE correlation_id = %s AND tenant_id = %s;
            """, (alert.correlation_id, tenant))
            row = cursor.fetchone()
            if row:
                incident_id, existing_alert_ids_raw, event_cnt = row[0], row[1], row[2]
                existing_alerts = json.loads(existing_alert_ids_raw or "[]")
                if alert.alert_id not in existing_alerts:
                    existing_alerts.append(alert.alert_id)
                cursor.execute(f"""
                    UPDATE {self.incidents_table}
                    SET alert_ids = %s, event_count = %s, updated_at = %s
                    WHERE incident_id = %s AND tenant_id = %s;
                """, (json.dumps(existing_alerts), event_cnt + 1, now_ts, incident_id, tenant))
            else:
                incident_id = f"inc_{uuid.uuid4().hex[:12]}"
                cursor.execute(f"""
                    INSERT INTO {self.incidents_table} (
                        incident_id, tenant_id, created_at, updated_at, title, description,
                        severity, status, agent_id, correlation_id, alert_ids,
                        event_count
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1);
                """, (
                    incident_id,
                    tenant,
                    now_ts,
                    now_ts,
                    f"Incident triggered by {alert.title}",
                    alert.description,
                    alert.severity,
                    IncidentStatus.OPEN.value,
                    alert.agent_id,
                    alert.correlation_id,
                    json.dumps([alert.alert_id]),
                ))

            # 2. Persist alert
            alert.incident_id = incident_id
            cursor.execute(f"""
                INSERT INTO {self.alerts_table} (
                    alert_id, tenant_id, timestamp, title, description, alert_type, severity,
                    status, agent_id, trigger_event_id, event_ids, correlation_id,
                    incident_id, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                alert.alert_id,
                tenant,
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
                now,
                now,
            ))
        return alert
