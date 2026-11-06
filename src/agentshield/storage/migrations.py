"""
PostgreSQL Schema Migration & Versioning System for AgentShield.

Provides concurrency-safe schema initialization, version tracking, and incremental
migrations across multi-instance serverless deployments.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, List, Optional

from agentshield.storage.connection import PostgresConnectionManager

logger = logging.getLogger("agentshield.storage.migrations")

# Advisory lock dedicated to DDL migrations (distinct from audit lock 71829103)
MIGRATION_ADVISORY_LOCK_ID = 71829100


@dataclass
class Migration:
    version: int
    name: str
    up: Callable[[Any], None]


def _execute_script(cursor: Any, script: str) -> None:
    """Executes a multi-statement DDL script cleanly across DB-API drivers."""
    for stmt in script.split(";"):
        cleaned = stmt.strip()
        if cleaned:
            cursor.execute(cleaned + ";")


def _migration_001_initial_schema(cursor: Any) -> None:
    """Migration 001: Core operational and simulator schemas."""
    # 1. Audit logs
    _execute_script(cursor, """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGSERIAL PRIMARY KEY,
            timestamp TEXT NOT NULL,
            agent VARCHAR(128) NOT NULL,
            tool VARCHAR(128) NOT NULL,
            arguments TEXT NOT NULL,
            decision VARCHAR(32) NOT NULL,
            allowed INTEGER NOT NULL,
            reasons TEXT NOT NULL,
            rules_triggered TEXT NOT NULL,
            risk_score DOUBLE PRECISION NOT NULL,
            severity VARCHAR(32) NOT NULL,
            risk_factors TEXT NOT NULL,
            execution_status VARCHAR(64) NOT NULL,
            error TEXT,
            policy_version_hash VARCHAR(128),
            prev_hash VARCHAR(128),
            record_hash VARCHAR(128),
            correlation_id VARCHAR(128),
            trace_id VARCHAR(128)
        );
        CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);
        CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent);
        CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_record_hash ON audit_logs(record_hash);
        CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_logs(correlation_id);
    """)

    # 2. Review queues (operational + simulator)
    for tbl in ("reviews", "sim_reviews"):
        _execute_script(cursor, f"""
            CREATE TABLE IF NOT EXISTS {tbl} (
                review_id VARCHAR(64) PRIMARY KEY,
                agent VARCHAR(128) NOT NULL,
                tool VARCHAR(128) NOT NULL,
                arguments TEXT NOT NULL,
                permissions TEXT NOT NULL,
                decision TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                expires_at DOUBLE PRECISION NOT NULL,
                status VARCHAR(32) NOT NULL DEFAULT 'pending',
                approver VARCHAR(128),
                reason TEXT,
                execution_status VARCHAR(64) NOT NULL DEFAULT 'not_started',
                error TEXT,
                idempotency_key VARCHAR(128),
                executed_at DOUBLE PRECISION,
                execution_worker_id VARCHAR(128),
                lease_expires_at DOUBLE PRECISION,
                updated_at DOUBLE PRECISION NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_{tbl}_status ON {tbl}(status);
            CREATE INDEX IF NOT EXISTS idx_{tbl}_expires ON {tbl}(expires_at);
            CREATE INDEX IF NOT EXISTS idx_{tbl}_idemp ON {tbl}(idempotency_key);
        """)

    # 3. Security events, alerts, incidents (operational + simulator)
    for pfx in ("", "sim_"):
        events_tbl = f"{pfx}security_events"
        alerts_tbl = f"{pfx}security_alerts"
        incidents_tbl = f"{pfx}security_incidents"

        _execute_script(cursor, f"""
            CREATE TABLE IF NOT EXISTS {events_tbl} (
                event_id VARCHAR(64) PRIMARY KEY,
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
            CREATE INDEX IF NOT EXISTS idx_{events_tbl}_agent ON {events_tbl}(agent_id);
            CREATE INDEX IF NOT EXISTS idx_{events_tbl}_corr ON {events_tbl}(correlation_id);

            CREATE TABLE IF NOT EXISTS {alerts_tbl} (
                alert_id VARCHAR(64) PRIMARY KEY,
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
            CREATE INDEX IF NOT EXISTS idx_{alerts_tbl}_status ON {alerts_tbl}(status);
            CREATE INDEX IF NOT EXISTS idx_{alerts_tbl}_corr ON {alerts_tbl}(correlation_id);

            CREATE TABLE IF NOT EXISTS {incidents_tbl} (
                incident_id VARCHAR(64) PRIMARY KEY,
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
            CREATE INDEX IF NOT EXISTS idx_{incidents_tbl}_status ON {incidents_tbl}(status);
            CREATE INDEX IF NOT EXISTS idx_{incidents_tbl}_corr ON {incidents_tbl}(correlation_id);
        """)

    # 4. Session store
    _execute_script(cursor, """
        CREATE TABLE IF NOT EXISTS session_revocations (
            token_hash VARCHAR(128) PRIMARY KEY,
            revoked_at DOUBLE PRECISION NOT NULL,
            user_id VARCHAR(128)
        );
        CREATE TABLE IF NOT EXISTS active_sessions (
            token_hash VARCHAR(128) PRIMARY KEY,
            user_id VARCHAR(128) NOT NULL,
            created_at DOUBLE PRECISION NOT NULL,
            expires_at DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON active_sessions(expires_at);
    """)

    # 5. Analyst investigation reports
    _execute_script(cursor, """
        CREATE TABLE IF NOT EXISTS investigation_reports (
            id BIGSERIAL PRIMARY KEY,
            report_id VARCHAR(64) UNIQUE NOT NULL,
            incident_id VARCHAR(64),
            correlation_id VARCHAR(64),
            created_at TEXT NOT NULL,
            schema_version VARCHAR(16) NOT NULL,
            analyst_model VARCHAR(64) NOT NULL,
            metadata TEXT NOT NULL,
            content TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_inv_reports_incident ON investigation_reports(incident_id);
        CREATE INDEX IF NOT EXISTS idx_inv_reports_correlation ON investigation_reports(correlation_id);
        CREATE INDEX IF NOT EXISTS idx_inv_reports_created ON investigation_reports(created_at);
    """)

    # 6. Simulator runs & failures
    _execute_script(cursor, """
        CREATE TABLE IF NOT EXISTS simulation_runs (
            run_id VARCHAR(64) PRIMARY KEY,
            scenario_id VARCHAR(64) NOT NULL,
            scenario_name VARCHAR(128) NOT NULL,
            attack_category VARCHAR(64) NOT NULL,
            timestamp DOUBLE PRECISION NOT NULL,
            actual_decision VARCHAR(32),
            expected_decision VARCHAR(32) NOT NULL,
            expectation_matched INTEGER NOT NULL,
            risk_score DOUBLE PRECISION,
            severity VARCHAR(32),
            latency_ms DOUBLE PRECISION NOT NULL,
            reasons TEXT NOT NULL,
            rules_triggered TEXT NOT NULL,
            execution_status VARCHAR(32) NOT NULL,
            tool_result TEXT,
            error_category VARCHAR(64),
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS simulation_failures (
            run_id VARCHAR(64) PRIMARY KEY,
            scenario_id VARCHAR(64) NOT NULL,
            scenario_name VARCHAR(128) NOT NULL,
            attack_category VARCHAR(64) NOT NULL,
            timestamp DOUBLE PRECISION NOT NULL,
            actual_decision VARCHAR(32),
            expected_decision VARCHAR(32) NOT NULL,
            expectation_matched INTEGER NOT NULL,
            risk_score DOUBLE PRECISION,
            severity VARCHAR(32),
            latency_ms DOUBLE PRECISION NOT NULL,
            reasons TEXT NOT NULL,
            rules_triggered TEXT NOT NULL,
            execution_status VARCHAR(32) NOT NULL,
            tool_result TEXT,
            error_category VARCHAR(64),
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sim_runs_ts ON simulation_runs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_sim_fail_ts ON simulation_failures(timestamp);
    """)


def _migration_002_rate_limit_schema(cursor: Any) -> None:
    """Migration 002: Distributed rate limit events table for shared multi-instance throttling."""
    _execute_script(cursor, """
        CREATE TABLE IF NOT EXISTS rate_limit_events (
            id BIGSERIAL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            timestamp DOUBLE PRECISION NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rate_limit_key_ts ON rate_limit_events(key, timestamp DESC);
    """)


def _migration_003_audit_correlation_tracing(cursor: Any) -> None:
    """Migration 003: Add correlation_id and trace_id columns and index to audit_logs."""
    cursor.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS correlation_id VARCHAR(128);")
    cursor.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS trace_id VARCHAR(128);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_logs(correlation_id);")


# Registry of ordered schema migrations
MIGRATIONS: List[Migration] = [
    Migration(
        version=1,
        name="001_initial_schema",
        up=_migration_001_initial_schema,
    ),
    Migration(
        version=2,
        name="002_rate_limit_schema",
        up=_migration_002_rate_limit_schema,
    ),
    Migration(
        version=3,
        name="003_audit_correlation_tracing",
        up=_migration_003_audit_correlation_tracing,
    ),
]


class MigrationManager:
    """Manages schema versioning and atomic, concurrency-safe DDL migrations."""

    def __init__(self, connection_manager: PostgresConnectionManager):
        self.connection_manager = connection_manager

    def _ensure_migrations_table(self, cursor: Any) -> None:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                applied_at TEXT NOT NULL
            );
        """)

    def get_applied_versions(self) -> List[int]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            self._ensure_migrations_table(cursor)
            cursor.execute("SELECT version FROM schema_migrations ORDER BY version ASC;")
            rows = cursor.fetchall()
            return [int(r[0]) for r in rows]

    def get_status(self) -> Dict[str, Any]:
        applied = set(self.get_applied_versions())
        status_list = []
        for m in MIGRATIONS:
            status_list.append({
                "version": m.version,
                "name": m.name,
                "applied": m.version in applied,
            })
        return {
            "current_version": max(applied) if applied else 0,
            "target_version": max(m.version for m in MIGRATIONS) if MIGRATIONS else 0,
            "migrations": status_list,
        }

    def run_migrations(self) -> int:
        """Applies any pending migrations under an advisory lock to prevent concurrent races.

        Returns the number of migrations newly applied.
        """
        applied_count = 0
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()

            # Acquire exclusive migration advisory lock for the duration of the transaction
            cursor.execute(f"SELECT pg_advisory_xact_lock({MIGRATION_ADVISORY_LOCK_ID});")

            # Ensure tracking table exists
            self._ensure_migrations_table(cursor)

            cursor.execute("SELECT version FROM schema_migrations;")
            applied = {int(r[0]) for r in cursor.fetchall()}

            for m in MIGRATIONS:
                if m.version not in applied:
                    logger.info(f"Applying schema migration {m.version}: {m.name}")
                    m.up(cursor)
                    now_ts = datetime.now(timezone.utc).isoformat()
                    cursor.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (%s, %s, %s);",
                        (m.version, m.name, now_ts),
                    )
                    applied_count += 1

        return applied_count
