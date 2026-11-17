"""
Unified Storage Factory for AgentShield.

Instantiates either SQLite or PostgreSQL storage backends based on environment
configuration, preserving full interface compatibility and ensuring isolation.
"""

from dataclasses import dataclass
import os
import tempfile
from typing import Any, Optional

from agentshield.analyst.store import ReportStore, SQLiteReportStore
from agentshield.audit.store import AuditStore, SQLiteAuditStore
from agentshield.events.store import EventStore, SQLiteEventStore
from agentshield.review.store import ReviewStore, SQLiteReviewStore
from agentshield.simulator.store import InMemorySimulationStore, SimulationStore, SqliteSimulationStore
from agentshield.storage.analyst import PostgresReportStore
from agentshield.storage.audit import PostgresAuditStore
from agentshield.storage.config import ConfigurationError, get_database_url, validate_database_url
from agentshield.storage.connection import PostgresConnectionManager
from agentshield.storage.events import PostgresEventStore
from agentshield.storage.migrations import MigrationManager
from agentshield.storage.review import PostgresReviewStore
from agentshield.storage.sessions import PostgresSessionStore
from agentshield.storage.simulation import PostgresSimulationStore
from agentshield.storage.tenants import PostgresTenantStore, SqliteTenantStore, TenantStore


@dataclass
class StoreBundle:
    """Encapsulates all operational and simulation storage instances."""
    audit_store: AuditStore
    review_store: ReviewStore
    event_store: EventStore
    report_store: ReportStore
    session_store: Any
    simulation_store: Any
    sim_review_store: ReviewStore
    sim_event_store: EventStore
    backend: str  # "postgres" or "sqlite"
    rate_limiter: Optional[Any] = None
    tenant_store: Optional[Any] = None


def create_postgres_stores(
    dsn: str,
    connection_manager: Optional[PostgresConnectionManager] = None,
) -> StoreBundle:
    """Instantiates a complete PostgreSQL store bundle for operational and simulation telemetry."""
    validate_database_url(dsn)
    cm = connection_manager or PostgresConnectionManager(dsn=dsn)

    # Concurrency-safe schema versioning and initial migration under advisory lock
    MigrationManager(cm).run_migrations()

    audit_store = PostgresAuditStore(dsn=dsn, connection_manager=cm)
    review_store = PostgresReviewStore(dsn=dsn, table_prefix="", connection_manager=cm)
    event_store = PostgresEventStore(dsn=dsn, table_prefix="", connection_manager=cm)
    report_store = PostgresReportStore(dsn=dsn, connection_manager=cm)
    session_store = PostgresSessionStore(dsn=dsn, connection_manager=cm)
    simulation_store = PostgresSimulationStore(dsn=dsn, connection_manager=cm)
    tenant_store = PostgresTenantStore(dsn=dsn, connection_manager=cm)

    # Isolated simulator storage using distinct table prefixes
    sim_review_store = PostgresReviewStore(dsn=dsn, table_prefix="sim_", connection_manager=cm)
    sim_event_store = PostgresEventStore(dsn=dsn, table_prefix="sim_", connection_manager=cm)

    from agentshield.reliability.rate_limiter import PostgresRateLimiter
    rate_limiter = PostgresRateLimiter(dsn=dsn, connection_manager=cm)

    return StoreBundle(
        audit_store=audit_store,
        review_store=review_store,
        event_store=event_store,
        report_store=report_store,
        session_store=session_store,
        simulation_store=simulation_store,
        sim_review_store=sim_review_store,
        sim_event_store=sim_event_store,
        backend="postgres",
        rate_limiter=rate_limiter,
        tenant_store=tenant_store,
    )


def create_stores(
    database_url: Optional[str] = None,
    audit_db_path: Optional[str] = None,
    review_db_path: Optional[str] = None,
    events_db_path: Optional[str] = None,
    reports_db_path: Optional[str] = None,
    sessions_db_path: Optional[str] = None,
    simulation_db_path: Optional[str] = None,
    tenants_db_path: Optional[str] = None,
    connection_manager: Optional[PostgresConnectionManager] = None,
) -> StoreBundle:
    """Creates the appropriate StoreBundle based on environment or explicit parameters.

    If database_url or AGENTSHIELD_DATABASE_URL/DATABASE_URL is provided,
    strictly initializes the PostgreSQL backend. Fails closed with ConfigurationError
    if the configuration or driver is invalid.
    Otherwise, initializes the default SQLite backend.
    """
    configured_db_url = get_database_url(database_url)

    if configured_db_url:
        # PostgreSQL backend explicitly selected
        return create_postgres_stores(configured_db_url, connection_manager=connection_manager)

    # SQLite backend (Default for local development and tests)
    audit_store = SQLiteAuditStore(db_path=audit_db_path)

    def _derive_companion_path(
        explicit_path: Optional[str],
        env_var: str,
        default_companion_name: str,
        prefix: str,
    ) -> Optional[str]:
        if explicit_path is not None:
            return explicit_path
        if audit_store.db_path == ":memory:":
            return ":memory:"
        if audit_store.db_path:
            audit_dir = os.path.dirname(audit_store.db_path)
            audit_base = os.path.basename(audit_store.db_path)
            comp_name = default_companion_name if audit_base == "agentshield_audit.db" else f"{prefix}_{audit_base}"
            return os.path.join(audit_dir, comp_name) if audit_dir else comp_name
        if os.environ.get(env_var):
            return os.environ[env_var]
        return None

    effective_review_path = _derive_companion_path(
        review_db_path, "AGENTSHIELD_REVIEW_DB", "agentshield_reviews.db", "review"
    )
    review_store = SQLiteReviewStore(db_path=effective_review_path)

    effective_events_path = _derive_companion_path(
        events_db_path, "AGENTSHIELD_EVENTS_DB", "agentshield_events.db", "events"
    )
    event_store = SQLiteEventStore(db_path=effective_events_path)

    effective_reports_path = _derive_companion_path(
        reports_db_path, "AGENTSHIELD_REPORTS_DB", "agentshield_reports.db", "reports"
    )
    report_store = SQLiteReportStore(db_path=effective_reports_path)

    effective_sessions_path = _derive_companion_path(
        sessions_db_path, "AGENTSHIELD_SESSIONS_DB", "agentshield_sessions.db", "sessions"
    )
    from agentshield.api.sessions import InMemorySessionStore, SqliteSessionStore
    if effective_sessions_path == ":memory:":
        session_store = InMemorySessionStore()
    else:
        sessions_file = effective_sessions_path or os.path.join(tempfile.gettempdir(), "agentshield_sessions.db")
        session_store = SqliteSessionStore(db_path=sessions_file)

    effective_simulation_path = _derive_companion_path(
        simulation_db_path, "AGENTSHIELD_SIMULATION_DB", "agentshield_simulation.db", "simulation"
    )
    if effective_simulation_path == ":memory:":
        simulation_store = InMemorySimulationStore()
    else:
        sim_file = effective_simulation_path or os.path.join(tempfile.gettempdir(), "agentshield_simulation.db")
        simulation_store = SqliteSimulationStore(db_path=sim_file)

    # Isolated simulator review and event stores
    effective_sim_review_path = _derive_companion_path(
        None, "AGENTSHIELD_SIM_REVIEW_DB", "agentshield_sim_reviews.db", "sim_review"
    )
    if effective_sim_review_path == ":memory:":
        sim_review_store = SQLiteReviewStore(db_path=":memory:")
    else:
        sim_review_file = effective_sim_review_path or os.path.join(tempfile.gettempdir(), "agentshield_sim_reviews.db")
        sim_review_store = SQLiteReviewStore(db_path=sim_review_file)

    effective_sim_events_path = _derive_companion_path(
        None, "AGENTSHIELD_SIM_EVENTS_DB", "agentshield_sim_events.db", "sim_events"
    )
    if effective_sim_events_path == ":memory:":
        sim_event_store = SQLiteEventStore(db_path=":memory:")
    else:
        sim_events_file = effective_sim_events_path or os.path.join(tempfile.gettempdir(), "agentshield_sim_events.db")
        sim_event_store = SQLiteEventStore(db_path=sim_events_file)

    from agentshield.reliability.rate_limiter import InMemoryRateLimiter, SqliteRateLimiter
    effective_rate_limit_path = _derive_companion_path(
        None, "AGENTSHIELD_RATE_LIMIT_DB", "agentshield_rate_limits.db", "rate_limit"
    )
    if effective_rate_limit_path == ":memory:":
        rate_limiter = InMemoryRateLimiter()
    else:
        rate_limit_file = effective_rate_limit_path or os.path.join(tempfile.gettempdir(), "agentshield_rate_limits.db")
        rate_limiter = SqliteRateLimiter(db_path=rate_limit_file)

    effective_tenants_path = _derive_companion_path(
        tenants_db_path, "AGENTSHIELD_TENANTS_DB", "agentshield_tenants.db", "tenants"
    )
    if effective_tenants_path == ":memory:":
        tenant_store = SqliteTenantStore(db_path=":memory:")
    else:
        tenants_file = effective_tenants_path or os.path.join(tempfile.gettempdir(), "agentshield_tenants.db")
        tenant_store = SqliteTenantStore(db_path=tenants_file)

    return StoreBundle(
        audit_store=audit_store,
        review_store=review_store,
        event_store=event_store,
        report_store=report_store,
        session_store=session_store,
        simulation_store=simulation_store,
        sim_review_store=sim_review_store,
        sim_event_store=sim_event_store,
        backend="sqlite",
        rate_limiter=rate_limiter,
        tenant_store=tenant_store,
    )
