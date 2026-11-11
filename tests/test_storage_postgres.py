"""
Unit and integration tests for AgentShield PostgreSQL persistent storage backend.

Clearly distinguishes mocked PostgreSQL adapter tests (using a shared DB-API
emulation engine) from tests against a live PostgreSQL instance.
"""

from concurrent.futures import ThreadPoolExecutor
import os
import re
import sqlite3
import threading
import time
from typing import Any, List, Optional
import pytest

from agentshield.analyst.models import AnalystSeverity, AnalysisReport
from agentshield.events.models import AlertStatus, EventSeverity, EventType, SecurityAlert, SecurityEvent, SecurityIncident
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.storage import (
    ConfigurationError,
    MigrationManager,
    PostgresAuditStore,
    PostgresConnectionManager,
    PostgresEventStore,
    PostgresReportStore,
    PostgresReviewStore,
    PostgresSessionStore,
    PostgresSimulationStore,
    create_postgres_stores,
    create_stores,
    get_storage_backend,
    migrate_sqlite_to_postgres,
    validate_database_url,
)


class MockPostgresCursor:
    """DB-API 2.0 cursor emulator for testing PostgreSQL queries on a shared in-memory engine."""

    def __init__(self, conn_wrapper: "MockPostgresConnection"):
        self._conn_wrapper = conn_wrapper
        self._conn = conn_wrapper._raw_conn
        self._cur = self._conn.cursor()
        self._engine = conn_wrapper._engine
        self._returning_row: Optional[Any] = None

    def execute(self, query: str, params: Optional[Any] = None) -> "MockPostgresCursor":
        # Check if transaction was previously aborted by an error (mirroring PostgreSQL behavior)
        if self._conn_wrapper.is_aborted:
            import psycopg.errors
            raise psycopg.errors.InFailedSqlTransaction(
                "current transaction is aborted, commands ignored until end of transaction block"
            )

        # Handle advisory lock simulation outside engine.lock to prevent deadlock
        if "pg_advisory_xact_lock" in query:
            if not self._conn_wrapper.holds_advisory:
                self._engine.advisory_lock.acquire()
                self._conn_wrapper.holds_advisory = True
            return self

        with self._engine.lock:
            # Translate PostgreSQL dialect to SQLite for hermetic mock execution
            clean_q = re.sub(r"\s+FOR\s+UPDATE\b", "", query, flags=re.IGNORECASE)
            clean_q = clean_q.replace("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
            clean_q = clean_q.replace("RETURNING id;", "")  # Handled via lastrowid if needed
            clean_q = clean_q.replace("%s", "?")

            # Handle PostgreSQL ALTER TABLE ... ADD COLUMN IF NOT EXISTS on SQLite
            alter_match = re.search(
                r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\w+)\s+([^;]+)",
                clean_q,
                re.IGNORECASE,
            )
            if alter_match:
                table_name = alter_match.group(1)
                col_name = alter_match.group(2)
                col_type = alter_match.group(3)
                self._cur.execute(f"PRAGMA table_info({table_name});")
                existing_cols = {row[1] for row in self._cur.fetchall()}
                if not existing_cols:
                    return self
                if col_name not in existing_cols:
                    clean_q = f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type};"
                else:
                    return self

            idx_match = re.search(r"CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+\w+\s+ON\s+(\w+)", clean_q, re.IGNORECASE)
            if idx_match:
                table_name = idx_match.group(1)
                self._cur.execute(f"PRAGMA table_info({table_name});")
                if not self._cur.fetchall():
                    return self

            try:
                if "RETURNING" in query.upper() and "INSERT" in query.upper():
                    # Execute insert
                    if params is not None:
                        self._cur.execute(clean_q, params)
                    else:
                        self._cur.execute(clean_q)
                    inserted_id = self._cur.lastrowid
                    # Emulate RETURNING id
                    self._returning_row = (inserted_id,)
                    return self
                else:
                    self._returning_row = None

                if params is not None:
                    self._cur.execute(clean_q, params)
                else:
                    self._cur.execute(clean_q)
                return self
            except Exception:
                self._conn_wrapper.is_aborted = True
                raise

    def fetchone(self) -> Any:
        with self._engine.lock:
            if getattr(self, "_returning_row", None) is not None:
                row = self._returning_row
                self._returning_row = None
                return row
            return self._cur.fetchone()

    def fetchall(self) -> List[Any]:
        with self._engine.lock:
            return self._cur.fetchall()

    @property
    def description(self) -> Any:
        return self._cur.description

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount


class MockPostgresConnection:
    """DB-API 2.0 connection wrapper for mock PostgreSQL adapter testing."""

    def __init__(self, raw_conn: sqlite3.Connection, engine: "MockPostgresEngine"):
        self._raw_conn = raw_conn
        self._engine = engine
        self.holds_advisory = False
        self.is_aborted = False
        self._sp_id = f"sp_{id(self)}_{int(time.time() * 1000000)}"
        with self._engine.lock:
            self._raw_conn.execute(f"SAVEPOINT {self._sp_id}")

    def cursor(self) -> MockPostgresCursor:
        return MockPostgresCursor(self)

    def commit(self) -> None:
        if self.is_aborted:
            import psycopg.errors
            raise psycopg.errors.InFailedSqlTransaction(
                "current transaction is aborted, commands ignored until end of transaction block"
            )
        with self._engine.lock:
            try:
                self._raw_conn.execute(f"RELEASE {self._sp_id}")
            except Exception:
                pass
            self._sp_id = f"sp_{id(self)}_{int(time.time() * 1000000)}"
            self._raw_conn.execute(f"SAVEPOINT {self._sp_id}")
        if self.holds_advisory:
            self.holds_advisory = False
            self._engine.advisory_lock.release()

    def rollback(self) -> None:
        self.is_aborted = False
        with self._engine.lock:
            try:
                self._raw_conn.execute(f"ROLLBACK TO {self._sp_id}")
                self._raw_conn.execute(f"RELEASE {self._sp_id}")
            except Exception:
                pass
            self._sp_id = f"sp_{id(self)}_{int(time.time() * 1000000)}"
            self._raw_conn.execute(f"SAVEPOINT {self._sp_id}")
        if self.holds_advisory:
            self.holds_advisory = False
            self._engine.advisory_lock.release()

    def close(self) -> None:
        with self._engine.lock:
            try:
                self._raw_conn.execute(f"RELEASE {self._sp_id}")
            except Exception:
                pass
        if self.holds_advisory:
            self.holds_advisory = False
            self._engine.advisory_lock.release()


class MockPostgresEngine:
    """Shared database engine providing independent connections to test cross-instance persistence."""

    def __init__(self):
        self.lock = threading.RLock()
        self.advisory_lock = threading.Lock()
        self.raw_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.raw_conn.isolation_level = None

    def get_connection(self) -> MockPostgresConnection:
        return MockPostgresConnection(self.raw_conn, self)


# -----------------------------------------------------------------------------
# Configuration and Validation Tests
# -----------------------------------------------------------------------------

def test_storage_backend_selection_and_validation(monkeypatch):
    """Verifies backend selection logic between SQLite and PostgreSQL."""
    monkeypatch.delenv("AGENTSHIELD_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    # 1. Default without env var is sqlite
    assert get_storage_backend() == "sqlite"

    # 2. Configured postgresql URL selects postgres
    valid_pg = "postgresql://agent_admin:secret@ep-db.neon.tech:5432/agentshield?sslmode=require"
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", valid_pg)
    assert get_storage_backend() == "postgres"

    # 3. Configured postgres:// fallback selects postgres
    valid_alt = "postgres://usr:pwd@localhost:5432/shield_db"
    monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", valid_alt)
    assert get_storage_backend() == "postgres"


def test_storage_backend_invalid_scheme_raises_configuration_error(monkeypatch):
    """Verifies that non-PostgreSQL schemes immediately fail with ConfigurationError without falling back."""
    invalid_schemes = [
        "mysql://user:pass@localhost/db",
        "sqlite:///tmp/test.db",
        "mongodb://localhost:27017/db",
        "redis://localhost:6379/0",
        "invalid-url-string",
        "",
    ]
    for url in invalid_schemes:
        monkeypatch.setenv("AGENTSHIELD_DATABASE_URL", url)
        with pytest.raises(ConfigurationError):
            get_storage_backend()


def test_storage_backend_driver_missing_raises_configuration_error(monkeypatch):
    """Verifies that selecting PostgreSQL without an installed driver raises ConfigurationError."""
    # Force driver check to report neither psycopg nor psycopg2
    monkeypatch.setattr("agentshield.storage.config.check_driver_available", lambda: (False, None))
    monkeypatch.setattr("agentshield.storage.connection.check_driver_available", lambda: (False, None))

    valid_pg = "postgresql://usr:pwd@localhost:5432/shield_db"
    with pytest.raises(ConfigurationError) as exc_info:
        PostgresConnectionManager(dsn=valid_pg)
    assert "no PostgreSQL driver" in str(exc_info.value)


# -----------------------------------------------------------------------------
# Mocked PostgreSQL Adapter Tests (Hermetic)
# -----------------------------------------------------------------------------

def test_postgres_adapter_mocked_store_bundle_initialization():
    """[MOCKED] Verifies complete initialization of StoreBundle for PostgreSQL."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(
        dsn="postgresql://mock:mock@localhost/mock_db",
        connection_factory=engine.get_connection,
    )

    bundle = create_postgres_stores(
        dsn="postgresql://mock:mock@localhost/mock_db",
        connection_manager=cm,
    )

    assert bundle.backend == "postgres"
    assert isinstance(bundle.audit_store, PostgresAuditStore)
    assert isinstance(bundle.review_store, PostgresReviewStore)
    assert isinstance(bundle.event_store, PostgresEventStore)
    assert isinstance(bundle.report_store, PostgresReportStore)
    assert isinstance(bundle.session_store, PostgresSessionStore)
    assert isinstance(bundle.simulation_store, PostgresSimulationStore)
    assert isinstance(bundle.sim_review_store, PostgresReviewStore)
    assert isinstance(bundle.sim_event_store, PostgresEventStore)

    # Verify table prefixing for simulator isolation
    assert bundle.review_store.table_name == "reviews"
    assert bundle.sim_review_store.table_name == "sim_reviews"
    assert bundle.event_store.events_table == "security_events"
    assert bundle.sim_event_store.events_table == "sim_security_events"


def test_postgres_adapter_mocked_cross_instance_audit_and_hash_chain():
    """[MOCKED] Verifies append-only audit logging and SHA-256 hash chaining across independent connections."""
    engine = MockPostgresEngine()

    # Instance A and Instance B represent two independent serverless execution containers
    cm_a = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    cm_b = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    store_a = PostgresAuditStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_a)
    store_b = PostgresAuditStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_b)

    # Instance A logs 2 decisions
    dec1 = Decision(allowed=True, decision=DecisionValue.ALLOW, reasons=["Policy passed"], risk_score=5.0, severity=RiskLevel.LOW, agent="agent1", tool="get_info")
    store_a.log_decision(dec1, {"id": 101})

    dec2 = Decision(allowed=False, decision=DecisionValue.BLOCK, reasons=["High risk"], risk_score=85.0, severity=RiskLevel.CRITICAL, agent="agent1", tool="delete_data")
    store_a.log_decision(dec2, {"id": 102})

    # Instance B logs 2 decisions
    dec3 = Decision(allowed=False, decision=DecisionValue.REVIEW, reasons=["Operator check required"], risk_score=60.0, severity=RiskLevel.HIGH, agent="agent2", tool="payout")
    store_b.log_decision(dec3, {"amount": 5000})

    dec4 = Decision(allowed=True, decision=DecisionValue.ALLOW, reasons=["Safe lookup"], risk_score=10.0, severity=RiskLevel.LOW, agent="agent2", tool="search")
    store_b.log_decision(dec4, {"query": "test"})

    # Instance A queries and sees all 4 records
    records = store_a.query(limit=10)
    assert len(records) == 4

    # Verify cryptographic integrity across instances
    integrity_a = store_a.verify_integrity()
    assert integrity_a["valid"] is True
    assert integrity_a["total_records"] == 4

    integrity_b = store_b.verify_integrity()
    assert integrity_b["valid"] is True
    assert integrity_b["total_records"] == 4


def test_postgres_adapter_mocked_concurrent_audit_writes():
    """[MOCKED] Verifies concurrent multi-threaded audit writes produce an unbroken hash chain."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    store = PostgresAuditStore(dsn="postgresql://m:m@lh/db", connection_manager=cm)

    def write_worker(idx: int):
        conn_mgr = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
        worker_store = PostgresAuditStore(dsn="postgresql://m:m@lh/db", connection_manager=conn_mgr)
        dec = Decision(
            allowed=(idx % 2 == 0),
            decision=DecisionValue.ALLOW if idx % 2 == 0 else DecisionValue.BLOCK,
            reasons=[f"Concurrent decision {idx}"],
            risk_score=float(idx * 2),
            severity=RiskLevel.LOW if idx % 2 == 0 else RiskLevel.HIGH,
            agent=f"worker_{idx}",
            tool="concurrent_tool",
        )
        worker_store.log_decision(dec, {"worker_idx": idx})

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_worker, range(20)))

    # Verify all 20 records exist and hash chain is unbroken
    records = store.query(limit=50)
    assert len(records) == 20

    check = store.verify_integrity()
    assert check["valid"] is True
    assert check["total_records"] == 20


def test_postgres_adapter_mocked_cross_instance_review_approval_consistency():
    """[MOCKED] Verifies race-free review claiming and approval across independent serverless instances."""
    engine = MockPostgresEngine()
    cm_a = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    cm_b = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    store_a = PostgresReviewStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_a)
    store_b = PostgresReviewStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_b)

    # Instance A enqueues a pending review
    rev_id = "rev_concurrent_test_1"
    now = time.time()
    dec = Decision(allowed=False, decision=DecisionValue.REVIEW, reasons=["High value"], risk_score=65.0, severity=RiskLevel.HIGH, agent="buyer", tool="create_invoice")
    store_a.enqueue_review(
        review_id=rev_id,
        agent="buyer",
        tool="create_invoice",
        arguments={"amount": 9000},
        permissions=["invoice.create"],
        decision=dec,
        created_at=now,
        expires_at=now + 3600,
        idempotency_key="idemp_101",
    )

    # Instance B sees the pending review in its queue
    pending_b = store_b.get_pending_reviews()
    assert len(pending_b) == 1
    assert pending_b[0]["review_id"] == rev_id

    # Instance A claims and approves the review
    claimed_a = store_a.claim_and_approve(rev_id, approver="admin_a", worker_id="worker_a")
    assert claimed_a is not None
    assert claimed_a["status"] == "approved"
    assert claimed_a["execution_status"] == "executing"

    # Instance B attempts to claim the same review -> returns None (already claimed)
    claimed_b = store_b.claim_and_approve(rev_id, approver="admin_b", worker_id="worker_b")
    assert claimed_b is None

    # Instance B verifies status is approved and execution state is executing
    assert store_b.get_status(rev_id) == "approved"
    assert store_b.get_execution_state(rev_id) == "executing"

    # Worker A completes execution
    success = store_a.mark_executed(rev_id, execution_state="succeeded", worker_id="worker_a")
    assert success is True
    assert store_b.get_execution_state(rev_id) == "succeeded"


def test_postgres_adapter_mocked_cross_instance_session_revocation():
    """[MOCKED] Verifies instant cross-instance session revocation consistency."""
    engine = MockPostgresEngine()
    cm_a = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    cm_b = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    store_a = PostgresSessionStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_a)
    store_b = PostgresSessionStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_b)

    token_hash = "token_hash_alpha_123"
    now = time.time()

    # Instance A saves an active session
    store_a.save_session(token_hash=token_hash, user="admin", created_at=now, expires_at=now + 3600)

    # Instance B verifies session is active (not revoked)
    assert store_b.is_revoked(token_hash) is False

    # Instance A revokes the session (e.g. POST /api/auth/logout)
    revoked = store_a.revoke_session(token_hash)
    assert revoked is True

    # Instance B immediately sees the session as revoked (eliminating serverless blind spot)
    assert store_b.is_revoked(token_hash) is True


def test_postgres_adapter_mocked_cross_instance_events_and_incident_correlation():
    """[MOCKED] Verifies atomic alert creation and incident correlation across independent instances."""
    engine = MockPostgresEngine()
    cm_a = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    cm_b = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    store_a = PostgresEventStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_a)
    store_b = PostgresEventStore(dsn="postgresql://m:m@lh/db", connection_manager=cm_b)

    corr_id = "corr_threat_group_1"
    evt1 = SecurityEvent(
        event_id="evt_pg_1",
        correlation_id=corr_id,
        agent_id="attacker_agent",
        tool="terminal_exec",
        event_type=EventType.SECURITY_FAILURE.value,
        severity=EventSeverity.CRITICAL.value,
        evidence=["Unauthorized execution attempt"],
    )
    store_a.record_event(evt1)

    alert1 = SecurityAlert(
        alert_id="alt_pg_1",
        title="Unauthorized Terminal Exec",
        description="Attempt to execute bash command",
        alert_type="privilege_violation",
        severity=EventSeverity.CRITICAL.value,
        status=AlertStatus.OPEN.value,
        agent_id="attacker_agent",
        correlation_id=corr_id,
        trigger_event_id="evt_pg_1",
        event_ids=["evt_pg_1"],
    )
    # Instance A creates first alert and auto-correlates an incident
    res_alert1 = store_a.record_alert_and_correlate(alert1, evt1)
    incident_id = res_alert1.incident_id
    assert incident_id is not None

    # Instance B records a second alert under the same correlation_id
    evt2 = SecurityEvent(
        event_id="evt_pg_2",
        correlation_id=corr_id,
        agent_id="attacker_agent",
        tool="cat_passwd",
        event_type=EventType.POLICY_VIOLATION.value,
        severity=EventSeverity.HIGH.value,
    )
    store_b.record_event(evt2)

    alert2 = SecurityAlert(
        alert_id="alt_pg_2",
        title="Sensitive File Read",
        description="Attempt to read passwd",
        alert_type="exfiltration",
        severity=EventSeverity.HIGH.value,
        status=AlertStatus.OPEN.value,
        agent_id="attacker_agent",
        correlation_id=corr_id,
        trigger_event_id="evt_pg_2",
        event_ids=["evt_pg_2"],
    )
    res_alert2 = store_b.record_alert_and_correlate(alert2, evt2)
    # Both alerts correlated into the same incident
    assert res_alert2.incident_id == incident_id

    # Instance A queries the incident and sees both alerts and updated event count
    inc = store_a.get_incident(incident_id)
    assert inc is not None
    assert inc.event_count == 2
    assert "alt_pg_1" in inc.alert_ids
    assert "alt_pg_2" in inc.alert_ids


def test_postgres_adapter_mocked_simulator_operational_isolation():
    """[MOCKED] Verifies that PostgreSQL simulation stores remain isolated from operational tables."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    # Operational stores
    op_review = PostgresReviewStore(dsn="postgresql://m:m@lh/db", table_prefix="", connection_manager=cm)
    op_events = PostgresEventStore(dsn="postgresql://m:m@lh/db", table_prefix="", connection_manager=cm)

    # Simulator isolated stores
    sim_review = PostgresReviewStore(dsn="postgresql://m:m@lh/db", table_prefix="sim_", connection_manager=cm)
    sim_events = PostgresEventStore(dsn="postgresql://m:m@lh/db", table_prefix="sim_", connection_manager=cm)

    # Enqueue review in simulator
    sim_dec = Decision(allowed=False, decision=DecisionValue.REVIEW, reasons=["Sim review"], risk_score=60.0, severity=RiskLevel.HIGH, agent="sim_agent", tool="sim_tool")
    sim_review.enqueue_review(
        review_id="sim_rev_1",
        agent="sim_agent",
        tool="sim_tool",
        arguments={},
        permissions=[],
        decision=sim_dec,
        created_at=time.time(),
        expires_at=time.time() + 300,
    )

    # Record event in simulator
    sim_evt = SecurityEvent(event_id="sim_evt_1", correlation_id="sim_corr_1", agent_id="sim_agent")
    sim_events.record_event(sim_evt)

    # VERIFY COMPLETE SEPARATION
    assert len(sim_review.get_pending_reviews()) == 1
    assert len(op_review.get_pending_reviews()) == 0, "Simulation review leaked into operational table"

    assert len(sim_events.query_events()) == 1
    assert len(op_events.query_events()) == 0, "Simulation event leaked into operational table"


def test_postgres_schema_migrations_and_lifecycle():
    """[MOCKED] Verifies schema migration tracking, advisory-lock protection, and idempotency."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    mgr = MigrationManager(cm)

    # 1. Initial state: no migrations applied yet
    from agentshield.storage.migrations import MIGRATIONS
    status_pre = mgr.get_status()
    assert status_pre["current_version"] == 0
    assert status_pre["target_version"] == len(MIGRATIONS)

    # 2. First run applies all migrations
    applied = mgr.run_migrations()
    assert applied == len(MIGRATIONS)

    status_post = mgr.get_status()
    assert status_post["current_version"] == len(MIGRATIONS)
    assert status_post["target_version"] == len(MIGRATIONS)
    assert status_post["migrations"][0]["applied"] is True

    # 3. Subsequent run is idempotent: 0 applied
    applied_again = mgr.run_migrations()
    assert applied_again == 0

    # 4. Tables created by migration exist
    with cm.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';")
        assert cur.fetchone() is not None


def test_postgres_migration_duplicate_column_idempotent():
    """Regression test: verifies migration 003 runs cleanly when columns already exist from migration 001."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    mgr = MigrationManager(cm)

    # 1. Run all migrations once (fresh init: migration 001 creates audit_logs with correlation_id/trace_id)
    applied = mgr.run_migrations()
    assert applied == 4
    assert mgr.get_applied_versions() == [1, 2, 3, 4]

    # 2. Directly invoke migration 003 again on the existing schema inside a transaction
    from agentshield.storage.migrations import _migration_003_audit_correlation_tracing
    with cm.get_connection() as conn:
        cur = conn.cursor()
        _migration_003_audit_correlation_tracing(cur)
        # Verify transaction remains valid: this would raise InFailedSqlTransaction if aborted
        cur.execute("SELECT COUNT(*) FROM audit_logs;")
        assert cur.fetchone() is not None

    # 3. Running run_migrations() again is idempotent
    assert mgr.run_migrations() == 0


def test_postgres_migration_legacy_schema_without_columns():
    """Regression test: verifies migration 003 successfully upgrades legacy schema missing correlation/trace columns."""
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    # Simulate legacy database: create audit_logs without correlation_id and trace_id
    with cm.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name VARCHAR(128) NOT NULL,
                applied_at TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                execution_status VARCHAR(64) NOT NULL
            );
        """)
        cur.execute("INSERT INTO schema_migrations (version, name, applied_at) VALUES (1, '001_legacy', '2026-01-01T00:00:00Z');")
        cur.execute("INSERT INTO schema_migrations (version, name, applied_at) VALUES (2, '002_rate_limit_schema', '2026-01-01T00:00:00Z');")

    mgr = MigrationManager(cm)
    status_pre = mgr.get_status()
    assert status_pre["current_version"] == 2
    assert status_pre["migrations"][2]["applied"] is False

    # Apply pending migrations (003 and 004 pending)
    applied = mgr.run_migrations()
    assert applied == 2
    assert mgr.get_applied_versions() == [1, 2, 3, 4]

    # Verify columns were added to audit_logs
    with cm.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(audit_logs);")
        col_names = {row[1] for row in cur.fetchall()}
        assert "correlation_id" in col_names
        assert "trace_id" in col_names
        assert "tenant_id" in col_names


def test_postgres_migration_genuine_failure_rolls_back():
    """Regression test: verifies that genuine migration failures roll back cleanly and are not swallowed."""
    from agentshield.storage.migrations import Migration, MIGRATIONS

    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)
    mgr = MigrationManager(cm)

    # 1. Apply existing migrations 1..4
    mgr.run_migrations()
    assert mgr.get_applied_versions() == [1, 2, 3, 4]

    # 2. Define a failing migration that creates a partial canary table and then fails
    def _failing_up(cursor):
        cursor.execute("CREATE TABLE partial_canary (id INTEGER PRIMARY KEY, note TEXT);")
        cursor.execute("THIS IS COMPLETELY INVALID SQL SYNTAX;")

    bad_migration = Migration(version=5, name="005_failing_migration", up=_failing_up)
    MIGRATIONS.append(bad_migration)

    try:
        with pytest.raises(Exception):
            mgr.run_migrations()

        # 3. Verify rollback removes partial_canary
        with cm.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='partial_canary';")
            assert cur.fetchone() is None, "partial_canary table should have been removed by rollback"

        # 4. Verify version 5 was NOT recorded in schema_migrations
        assert mgr.get_applied_versions() == [1, 2, 3, 4]
        status = mgr.get_status()
        assert status["current_version"] == 4

        # 5. Verify the connection can be used successfully afterward
        with cm.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM audit_logs;")
            assert cur.fetchone() is not None
            cur.execute("CREATE TABLE post_recovery_test (id INTEGER PRIMARY KEY);")
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='post_recovery_test';")
            assert cur.fetchone() is not None
    finally:
        MIGRATIONS.remove(bad_migration)


def test_sqlite_to_postgres_safe_migration(tmp_path):
    """[MOCKED] Verifies safe, repeatable data migration from SQLite to PostgreSQL with hash chain verification."""
    # 1. Populate real SQLite databases
    audit_db = str(tmp_path / "sqlite_audit.db")
    review_db = str(tmp_path / "sqlite_reviews.db")
    events_db = str(tmp_path / "sqlite_events.db")
    reports_db = str(tmp_path / "sqlite_reports.db")
    sessions_db = str(tmp_path / "sqlite_sessions.db")
    sim_db = str(tmp_path / "sqlite_sim.db")

    from agentshield.audit.store import SQLiteAuditStore
    from agentshield.review.store import SQLiteReviewStore
    from agentshield.events.store import SQLiteEventStore

    sq_audit = SQLiteAuditStore(db_path=audit_db)
    # Write 3 chained audit decisions in SQLite
    for i in range(3):
        dec = Decision(
            allowed=(i % 2 == 0),
            decision=DecisionValue.ALLOW if i % 2 == 0 else DecisionValue.BLOCK,
            reasons=[f"Rule {i}"],
            risk_score=float(i * 10),
            severity=RiskLevel.LOW,
            agent="sqlite_agent",
            tool=f"tool_{i}",
        )
        sq_audit.log_decision(dec, arguments={"arg": i})

    # Verify SQLite chain is intact before migration
    assert sq_audit.verify_integrity()["valid"] is True

    sq_review = SQLiteReviewStore(db_path=review_db)
    rev_dec = Decision(allowed=False, decision=DecisionValue.REVIEW, reasons=["Rev"], risk_score=50.0, severity=RiskLevel.MEDIUM, agent="agent_x", tool="tool_x")
    sq_review.enqueue_review("rev_mig_1", "agent_x", "tool_x", {"amount": 100}, [], rev_dec, time.time(), time.time() + 300)

    sq_events = SQLiteEventStore(db_path=events_db)
    evt = SecurityEvent(event_id="evt_mig_1", correlation_id="corr_mig_1", agent_id="agent_x", tool="tool_x")
    sq_events.record_event(evt)
    alt = SecurityAlert(alert_id="alt_mig_1", correlation_id="corr_mig_1", agent_id="agent_x", trigger_event_id="evt_mig_1", event_ids=["evt_mig_1"])
    sq_events.record_alert_and_correlate(alt, evt)

    # 2. Target PostgreSQL setup (mocked engine)
    engine = MockPostgresEngine()
    cm = PostgresConnectionManager(dsn="postgresql://m:m@lh/db", connection_factory=engine.get_connection)

    paths = {
        "audit": audit_db,
        "review": review_db,
        "events": events_db,
        "reports": reports_db,
        "sessions": sessions_db,
        "simulation": sim_db,
    }

    # 3. Test dry_run=True (validates but rolls back)
    dry_summary = migrate_sqlite_to_postgres("postgresql://m:m@lh/db", sqlite_paths=paths, connection_manager=cm, dry_run=True)
    assert dry_summary.dry_run is True
    assert dry_summary.audit_records_migrated == 3
    assert dry_summary.reviews_migrated == 1
    assert dry_summary.events_migrated == 1
    # Check that nothing actually persisted in target
    with cm.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM audit_logs;")
        assert cur.fetchone()[0] == 0

    # 4. Test live migration commit
    summary = migrate_sqlite_to_postgres("postgresql://m:m@lh/db", sqlite_paths=paths, connection_manager=cm, dry_run=False)
    assert summary.audit_records_migrated == 3
    assert summary.reviews_migrated == 1
    assert summary.events_migrated == 1
    assert summary.audit_chain_verified is True
    assert len(summary.errors) == 0

    # 5. Verify PostgreSQL stores read the migrated data and hash chain is unbroken!
    pg_audit = PostgresAuditStore(dsn="postgresql://m:m@lh/db", connection_manager=cm)
    pg_integrity = pg_audit.verify_integrity()
    assert pg_integrity["valid"] is True
    assert pg_integrity["records_checked"] == 3

    pg_review = PostgresReviewStore(dsn="postgresql://m:m@lh/db", connection_manager=cm)
    pending = pg_review.get_pending_reviews()
    assert len(pending) == 1
    assert pending[0]["review_id"] == "rev_mig_1"

    # 6. Verify Repeatability (running again does not fail or duplicate)
    summary_repeat = migrate_sqlite_to_postgres("postgresql://m:m@lh/db", sqlite_paths=paths, connection_manager=cm, dry_run=False)
    assert summary_repeat.reviews_migrated == 0  # skipped already existing
    assert len(summary_repeat.errors) == 0


# -----------------------------------------------------------------------------
# Live PostgreSQL Tests (Skipped unless AGENTSHIELD_TEST_POSTGRES_URL is set)
# -----------------------------------------------------------------------------

def test_live_postgres_instance():
    """[LIVE] Executes end-to-end against a real PostgreSQL instance if configured."""
    live_url = os.environ.get("AGENTSHIELD_TEST_POSTGRES_URL") or os.environ.get("TEST_DATABASE_URL")
    if not live_url:
        pytest.skip("AGENTSHIELD_TEST_POSTGRES_URL is not set; skipping live PostgreSQL test")

    validate_database_url(live_url)
    cm = PostgresConnectionManager(dsn=live_url)
    mgr = MigrationManager(cm)

    # 1. Run migrations on live PostgreSQL (verifies no InFailedSqlTransaction)
    applied = mgr.run_migrations()
    assert isinstance(applied, int)
    applied_versions = mgr.get_applied_versions()
    assert 1 in applied_versions
    assert 2 in applied_versions
    assert 3 in applied_versions

    # 2. Verify idempotency on live PostgreSQL
    assert mgr.run_migrations() == 0

    stores = create_postgres_stores(live_url, connection_manager=cm)

    # Live test audit write and hash verification
    dec = Decision(
        allowed=True,
        decision=DecisionValue.ALLOW,
        reasons=["Live PostgreSQL validation"],
        risk_score=1.0,
        severity=RiskLevel.LOW,
        agent="live_tester",
        tool="ping",
    )
    rec_id = stores.audit_store.log_decision(dec, {"test": True})
    assert rec_id > 0

    integrity = stores.audit_store.verify_integrity()
    assert integrity["valid"] is True
