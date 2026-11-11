"""
PostgreSQL Session Store for AgentShield.

Provides multi-instance session revocation consistency across serverless workers.
"""

import logging
import time
from typing import Any, Optional

from agentshield.storage.connection import PostgresConnectionManager

logger = logging.getLogger("agentshield.storage.sessions")


class PostgresSessionStore:
    """PostgreSQL implementation of SessionStore protocol."""

    def __init__(self, dsn: str, connection_manager: Optional[PostgresConnectionManager] = None):
        self.connection_manager = connection_manager or PostgresConnectionManager(dsn=dsn)
        self.init_db()

    def init_db(self) -> None:
        """Initializes sessions table and index."""
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash VARCHAR(128) PRIMARY KEY,
                    "user" VARCHAR(128) NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
                    role VARCHAR(64) NOT NULL DEFAULT 'tenant_admin'
                );
            """)
            cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';")
            cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS role VARCHAR(64) NOT NULL DEFAULT 'tenant_admin';")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);")

    def save_session(
        self,
        token_hash: str,
        user: str,
        created_at: float,
        expires_at: float,
        tenant_id: str = "default",
        role: str = "tenant_admin",
    ) -> None:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions (token_hash, "user", created_at, expires_at, revoked, tenant_id, role)
                VALUES (%s, %s, %s, %s, 0, %s, %s)
                ON CONFLICT (token_hash) DO UPDATE SET
                    "user" = EXCLUDED."user",
                    expires_at = EXCLUDED.expires_at,
                    revoked = 0,
                    tenant_id = EXCLUDED.tenant_id,
                    role = EXCLUDED.role;
            """, (token_hash, user, created_at, expires_at, tenant_id, role))

    def is_revoked(self, token_hash: str) -> bool:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT revoked, expires_at FROM sessions WHERE token_hash = %s;', (token_hash,))
            row = cursor.fetchone()
            if not row:
                return False
            revoked, expires_at = row[0], row[1]
            if revoked == 1 or expires_at < time.time():
                return True
            return False

    def revoke_session(self, token_hash: str) -> bool:
        now = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE sessions SET revoked = 1 WHERE token_hash = %s;', (token_hash,))
            if cursor.rowcount == 0:
                cursor.execute("""
                    INSERT INTO sessions (token_hash, "user", created_at, expires_at, revoked)
                    VALUES (%s, 'unknown', %s, %s, 1);
                """, (token_hash, now, now + 86400))
            return True

    def get_session(self, token_hash: str) -> Optional[Any]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT token_hash, "user", created_at, expires_at, revoked, tenant_id, role FROM sessions WHERE token_hash = %s;',
                (token_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            from agentshield.api.sessions import SessionRecord
            return SessionRecord(
                token_hash=row[0],
                user=row[1],
                created_at=float(row[2]),
                expires_at=float(row[3]),
                revoked=bool(row[4]),
                tenant_id=row[5] if len(row) > 5 else "default",
                role=row[6] if len(row) > 6 else "tenant_admin",
            )

    def cleanup_expired(self) -> int:
        now = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE expires_at < %s;", (now,))
            return cursor.rowcount

