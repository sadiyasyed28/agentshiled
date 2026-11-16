"""
AgentShield Storage Subsystem.

Provides unified storage abstractions supporting SQLite for local development
and PostgreSQL for multi-instance serverless deployments.
"""

from agentshield.storage.analyst import PostgresReportStore
from agentshield.storage.audit import PostgresAuditStore
from agentshield.storage.config import (
    ConfigurationError,
    check_driver_available,
    get_database_url,
    get_storage_backend,
    validate_database_url,
)
from agentshield.storage.connection import PostgresConnectionManager
from agentshield.storage.events import PostgresEventStore
from agentshield.storage.factory import StoreBundle, create_postgres_stores, create_stores
from agentshield.storage.migrate_sqlite import MigrationSummary, migrate_sqlite_to_postgres
from agentshield.storage.migrations import MIGRATIONS, MigrationManager
from agentshield.storage.review import PostgresReviewStore
from agentshield.storage.sessions import PostgresSessionStore
from agentshield.storage.simulation import PostgresSimulationStore
from agentshield.storage.tenants import (
    PostgresTenantStore,
    SqliteTenantStore,
    Tenant,
    TenantApiKey,
    TenantStore,
)

__all__ = [
    "ConfigurationError",
    "MIGRATIONS",
    "MigrationManager",
    "MigrationSummary",
    "PostgresAuditStore",
    "PostgresConnectionManager",
    "PostgresEventStore",
    "PostgresReportStore",
    "PostgresReviewStore",
    "PostgresSessionStore",
    "PostgresSimulationStore",
    "PostgresTenantStore",
    "SqliteTenantStore",
    "StoreBundle",
    "Tenant",
    "TenantApiKey",
    "TenantStore",
    "check_driver_available",
    "create_postgres_stores",
    "create_stores",
    "get_database_url",
    "get_storage_backend",
    "migrate_sqlite_to_postgres",
    "validate_database_url",
]

