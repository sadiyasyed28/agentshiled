"""
PostgreSQL Connection Manager for AgentShield serverless persistence.

Supports direct drivers (psycopg 3 and psycopg2) and mock/custom connection
factories for hermetic testing. Implements connection lifecycle management
optimized for serverless cold-start and connection-pooling constraints.
"""

from contextlib import contextmanager
import logging
import threading
from typing import Any, Callable, Generator, Optional

from agentshield.storage.config import ConfigurationError, check_driver_available, validate_database_url

logger = logging.getLogger("agentshield.storage.postgres")


class PostgresConnectionManager:
    """Manages connections to PostgreSQL across multi-instance serverless runtimes."""

    def __init__(
        self,
        dsn: str,
        connection_factory: Optional[Callable[[], Any]] = None,
        timeout: float = 30.0,
    ):
        validate_database_url(dsn)
        self.dsn = dsn
        self.timeout = timeout
        self.connection_factory = connection_factory
        self._lock = threading.Lock()

        # Check driver if no custom factory is provided
        if self.connection_factory is None:
            available, driver_name = check_driver_available()
            if not available:
                raise ConfigurationError(
                    "PostgreSQL backend selected via AGENTSHIELD_DATABASE_URL, but no PostgreSQL driver "
                    "(psycopg or psycopg2) is installed in the Python environment. "
                    "Install it with: pip install 'agentshield[postgres]'"
                )
            self._driver_name = driver_name
        else:
            self._driver_name = "custom_factory"

    def create_raw_connection(self) -> Any:
        """Instantiates a single raw DB-API compliant connection."""
        if self.connection_factory is not None:
            return self.connection_factory()

        if self._driver_name == "psycopg":
            import psycopg
            return psycopg.connect(self.dsn, autocommit=False)
        elif self._driver_name == "psycopg2":
            import psycopg2
            return psycopg2.connect(self.dsn)
        else:
            raise ConfigurationError(f"No valid PostgreSQL driver available: {self._driver_name}")

    @contextmanager
    def get_connection(self) -> Generator[Any, None, None]:
        """Provides a transactional database connection context.

        Ensures automatic rollback on unhandled exceptions and proper cleanup.
        """
        conn = self.create_raw_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception as rb_err:
                logger.warning(f"Error rolling back connection: {rb_err}")
            raise
        finally:
            try:
                conn.close()
            except Exception as close_err:
                logger.warning(f"Error closing connection: {close_err}")

