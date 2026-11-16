"""
Tenant and API Key storage for AgentShield.

Provides persistent multi-tenant registration, password hashing,
cryptographic API key generation, hash-only key persistence,
and key rotation/revocation for SQLite and PostgreSQL.
"""

from dataclasses import dataclass
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, List, Optional, Protocol, Tuple
import uuid

logger = logging.getLogger("agentshield.storage.tenants")


class TenantAlreadyExistsError(Exception):
    """Raised when registering an email or tenant ID that already exists."""
    pass


class InvalidCredentialsError(Exception):
    """Raised when authentication fails due to incorrect credentials."""
    pass


class KeyNotFoundError(Exception):
    """Raised when an API key is not found or not owned by the tenant."""
    pass


@dataclass
class Tenant:
    tenant_id: str
    name: str
    owner_email: str
    password_hash: str
    password_salt: str
    created_at: float
    updated_at: float


@dataclass
class TenantApiKey:
    key_id: str
    tenant_id: str
    name: str
    key_hash: str
    prefix: str
    last_four: str
    created_at: float
    revoked_at: Optional[float] = None
    last_used_at: Optional[float] = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None

    @property
    def masked(self) -> str:
        return f"{self.prefix}_...{self.last_four}"


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
    
    Returns:
        (hex_hash, hex_salt)
    """
    if not salt:
        salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        100_000,
    )
    return derived.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash."""
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        100_000,
    )
    return hmac.compare_digest(derived.hex(), password_hash)


def generate_api_key(prefix: str = "ash_live") -> Tuple[str, str, str, str]:
    """Generates a cryptographically secure random API key.
    
    Returns:
        (full_plaintext_key, key_hash, prefix, last_four)
    """
    clean_prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix).strip("_") or "ash_live"
    raw_token = secrets.token_urlsafe(32)
    full_key = f"{clean_prefix}_{raw_token}"
    key_hash = hashlib.sha256(full_key.encode("utf-8")).hexdigest()
    last_four = full_key[-4:]
    return full_key, key_hash, clean_prefix, last_four


class TenantStore(Protocol):
    """Protocol for tenant workspace and API key persistence."""

    def create_tenant(
        self,
        name: str,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
    ) -> Tenant:
        ...

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        ...

    def get_tenant_by_email(self, email: str) -> Optional[Tenant]:
        ...

    def authenticate_tenant(self, email: str, password: str) -> Optional[Tenant]:
        ...

    def create_api_key(
        self,
        tenant_id: str,
        name: str = "Default Key",
        prefix: str = "ash_live",
    ) -> Tuple[TenantApiKey, str]:
        ...

    def get_key_by_hash(self, key_hash: str) -> Optional[TenantApiKey]:
        ...

    def list_api_keys(self, tenant_id: str) -> List[TenantApiKey]:
        ...

    def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        ...

    def rotate_api_key(
        self,
        tenant_id: str,
        key_id: str,
        name: Optional[str] = None,
    ) -> Tuple[TenantApiKey, str]:
        ...

    def touch_key(self, key_id: str) -> None:
        ...


class SqliteTenantStore:
    """Persistent SQLite-backed tenant and API key store."""

    def __init__(self, db_path: str = ":memory:", timeout: float = 30.0):
        self.db_path = db_path
        self.timeout = timeout
        self._lock = threading.Lock()
        self._shared_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", timeout=self.timeout, check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path, timeout=self.timeout)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            if self.db_path != ":memory:":
                db_dir = os.path.dirname(os.path.abspath(self.db_path))
                os.makedirs(db_dir, exist_ok=True)
            with self._get_connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tenants (
                        tenant_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        owner_email TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        password_salt TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tenants_email ON tenants(owner_email)")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS tenant_api_keys (
                        key_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        prefix TEXT NOT NULL,
                        last_four TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        revoked_at REAL,
                        last_used_at REAL,
                        FOREIGN KEY(tenant_id) REFERENCES tenants(tenant_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant ON tenant_api_keys(tenant_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tenant_keys_hash ON tenant_api_keys(key_hash)")

    def create_tenant(
        self,
        name: str,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
    ) -> Tenant:
        norm_email = email.strip().lower()
        if not norm_email or "@" not in norm_email:
            raise ValueError("A valid email address is required")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not name or not name.strip():
            raise ValueError("Workspace name cannot be empty")

        clean_name = name.strip()
        t_id = tenant_id or f"t_{uuid.uuid4().hex[:12]}"
        now = time.time()
        pwd_hash, salt = hash_password(password)

        with self._lock:
            with self._get_connection() as conn:
                # Check existing email
                cur = conn.cursor()
                cur.execute("SELECT tenant_id FROM tenants WHERE owner_email = ?", (norm_email,))
                if cur.fetchone():
                    raise TenantAlreadyExistsError(f"A tenant with email '{norm_email}' already exists")

                cur.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (t_id,))
                if cur.fetchone():
                    raise TenantAlreadyExistsError(f"Tenant ID '{t_id}' already exists")

                conn.execute(
                    """
                    INSERT INTO tenants (tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (t_id, clean_name, norm_email, pwd_hash, salt, now, now),
                )

        return Tenant(
            tenant_id=t_id,
            name=clean_name,
            owner_email=norm_email,
            password_hash=pwd_hash,
            password_salt=salt,
            created_at=now,
            updated_at=now,
        )

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at FROM tenants WHERE tenant_id = ?",
                    (tenant_id,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return Tenant(
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    owner_email=row["owner_email"],
                    password_hash=row["password_hash"],
                    password_salt=row["password_salt"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )

    def get_tenant_by_email(self, email: str) -> Optional[Tenant]:
        norm_email = email.strip().lower()
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at FROM tenants WHERE owner_email = ?",
                    (norm_email,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return Tenant(
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    owner_email=row["owner_email"],
                    password_hash=row["password_hash"],
                    password_salt=row["password_salt"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )

    def authenticate_tenant(self, email: str, password: str) -> Optional[Tenant]:
        tenant = self.get_tenant_by_email(email)
        if not tenant:
            return None
        if verify_password(password, tenant.password_hash, tenant.password_salt):
            return tenant
        return None

    def create_api_key(
        self,
        tenant_id: str,
        name: str = "Default Key",
        prefix: str = "ash_live",
    ) -> Tuple[TenantApiKey, str]:
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise KeyNotFoundError(f"Tenant '{tenant_id}' does not exist")

        key_id = f"key_{uuid.uuid4().hex[:12]}"
        full_key, key_hash, pfx, last_four = generate_api_key(prefix)
        now = time.time()
        key_name = name.strip() or "API Key"

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO tenant_api_keys (key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (key_id, tenant_id, key_name, key_hash, pfx, last_four, now),
                )

        record = TenantApiKey(
            key_id=key_id,
            tenant_id=tenant_id,
            name=key_name,
            key_hash=key_hash,
            prefix=pfx,
            last_four=last_four,
            created_at=now,
            revoked_at=None,
            last_used_at=None,
        )
        return record, full_key

    def get_key_by_hash(self, key_hash: str) -> Optional[TenantApiKey]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at
                    FROM tenant_api_keys
                    WHERE key_hash = ?
                    """,
                    (key_hash,),
                )
                row = cur.fetchone()
                if not row:
                    return None
                return TenantApiKey(
                    key_id=row["key_id"],
                    tenant_id=row["tenant_id"],
                    name=row["name"],
                    key_hash=row["key_hash"],
                    prefix=row["prefix"],
                    last_four=row["last_four"],
                    created_at=row["created_at"],
                    revoked_at=row["revoked_at"],
                    last_used_at=row["last_used_at"],
                )

    def list_api_keys(self, tenant_id: str) -> List[TenantApiKey]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at
                    FROM tenant_api_keys
                    WHERE tenant_id = ?
                    ORDER BY created_at DESC
                    """,
                    (tenant_id,),
                )
                return [
                    TenantApiKey(
                        key_id=row["key_id"],
                        tenant_id=row["tenant_id"],
                        name=row["name"],
                        key_hash=row["key_hash"],
                        prefix=row["prefix"],
                        last_four=row["last_four"],
                        created_at=row["created_at"],
                        revoked_at=row["revoked_at"],
                        last_used_at=row["last_used_at"],
                    )
                    for row in cur.fetchall()
                ]

    def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        now = time.time()
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE tenant_api_keys
                    SET revoked_at = ?
                    WHERE key_id = ? AND tenant_id = ? AND revoked_at IS NULL
                    """,
                    (now, key_id, tenant_id),
                )
                return cur.rowcount > 0

    def rotate_api_key(
        self,
        tenant_id: str,
        key_id: str,
        name: Optional[str] = None,
    ) -> Tuple[TenantApiKey, str]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT name, prefix FROM tenant_api_keys WHERE key_id = ? AND tenant_id = ?",
                    (key_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    raise KeyNotFoundError(f"Key '{key_id}' does not exist for tenant '{tenant_id}'")
                old_name = row["name"]
                old_prefix = row["prefix"]

        self.revoke_api_key(tenant_id, key_id)
        new_name = name.strip() if name and name.strip() else f"{old_name} (Rotated)"
        return self.create_api_key(tenant_id=tenant_id, name=new_name, prefix=old_prefix)

    def touch_key(self, key_id: str) -> None:
        now = time.time()
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE tenant_api_keys SET last_used_at = ? WHERE key_id = ?",
                    (now, key_id),
                )


class PostgresTenantStore:
    """PostgreSQL-backed tenant and API key store."""

    def __init__(self, dsn: str, connection_manager: Optional[Any] = None):
        from agentshield.storage.connection import PostgresConnectionManager
        self.connection_manager = connection_manager or PostgresConnectionManager(dsn=dsn)
        self.init_db()

    def init_db(self) -> None:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id VARCHAR(128) PRIMARY KEY,
                    name VARCHAR(256) NOT NULL,
                    owner_email VARCHAR(256) NOT NULL UNIQUE,
                    password_hash VARCHAR(128) NOT NULL,
                    password_salt VARCHAR(128) NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenants_email ON tenants(owner_email);")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tenant_api_keys (
                    key_id VARCHAR(64) PRIMARY KEY,
                    tenant_id VARCHAR(128) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
                    name VARCHAR(256) NOT NULL,
                    key_hash VARCHAR(128) NOT NULL UNIQUE,
                    prefix VARCHAR(32) NOT NULL,
                    last_four VARCHAR(16) NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    revoked_at DOUBLE PRECISION,
                    last_used_at DOUBLE PRECISION
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_keys_tenant ON tenant_api_keys(tenant_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tenant_keys_hash ON tenant_api_keys(key_hash);")

    def create_tenant(
        self,
        name: str,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
    ) -> Tenant:
        norm_email = email.strip().lower()
        if not norm_email or "@" not in norm_email:
            raise ValueError("A valid email address is required")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not name or not name.strip():
            raise ValueError("Workspace name cannot be empty")

        clean_name = name.strip()
        t_id = tenant_id or f"t_{uuid.uuid4().hex[:12]}"
        now = time.time()
        pwd_hash, salt = hash_password(password)

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT tenant_id FROM tenants WHERE owner_email = %s;", (norm_email,))
            if cursor.fetchone():
                raise TenantAlreadyExistsError(f"A tenant with email '{norm_email}' already exists")

            cursor.execute("SELECT tenant_id FROM tenants WHERE tenant_id = %s;", (t_id,))
            if cursor.fetchone():
                raise TenantAlreadyExistsError(f"Tenant ID '{t_id}' already exists")

            cursor.execute(
                """
                INSERT INTO tenants (tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """,
                (t_id, clean_name, norm_email, pwd_hash, salt, now, now),
            )

        return Tenant(
            tenant_id=t_id,
            name=clean_name,
            owner_email=norm_email,
            password_hash=pwd_hash,
            password_salt=salt,
            created_at=now,
            updated_at=now,
        )

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at FROM tenants WHERE tenant_id = %s;",
                (tenant_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Tenant(
                tenant_id=row[0],
                name=row[1],
                owner_email=row[2],
                password_hash=row[3],
                password_salt=row[4],
                created_at=row[5],
                updated_at=row[6],
            )

    def get_tenant_by_email(self, email: str) -> Optional[Tenant]:
        norm_email = email.strip().lower()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT tenant_id, name, owner_email, password_hash, password_salt, created_at, updated_at FROM tenants WHERE owner_email = %s;",
                (norm_email,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return Tenant(
                tenant_id=row[0],
                name=row[1],
                owner_email=row[2],
                password_hash=row[3],
                password_salt=row[4],
                created_at=row[5],
                updated_at=row[6],
            )

    def authenticate_tenant(self, email: str, password: str) -> Optional[Tenant]:
        tenant = self.get_tenant_by_email(email)
        if not tenant:
            return None
        if verify_password(password, tenant.password_hash, tenant.password_salt):
            return tenant
        return None

    def create_api_key(
        self,
        tenant_id: str,
        name: str = "Default Key",
        prefix: str = "ash_live",
    ) -> Tuple[TenantApiKey, str]:
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise KeyNotFoundError(f"Tenant '{tenant_id}' does not exist")

        key_id = f"key_{uuid.uuid4().hex[:12]}"
        full_key, key_hash, pfx, last_four = generate_api_key(prefix)
        now = time.time()
        key_name = name.strip() or "API Key"

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tenant_api_keys (key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NULL, NULL);
                """,
                (key_id, tenant_id, key_name, key_hash, pfx, last_four, now),
            )

        record = TenantApiKey(
            key_id=key_id,
            tenant_id=tenant_id,
            name=key_name,
            key_hash=key_hash,
            prefix=pfx,
            last_four=last_four,
            created_at=now,
            revoked_at=None,
            last_used_at=None,
        )
        return record, full_key

    def get_key_by_hash(self, key_hash: str) -> Optional[TenantApiKey]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at
                FROM tenant_api_keys
                WHERE key_hash = %s;
                """,
                (key_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return TenantApiKey(
                key_id=row[0],
                tenant_id=row[1],
                name=row[2],
                key_hash=row[3],
                prefix=row[4],
                last_four=row[5],
                created_at=row[6],
                revoked_at=row[7],
                last_used_at=row[8],
            )

    def list_api_keys(self, tenant_id: str) -> List[TenantApiKey]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT key_id, tenant_id, name, key_hash, prefix, last_four, created_at, revoked_at, last_used_at
                FROM tenant_api_keys
                WHERE tenant_id = %s
                ORDER BY created_at DESC;
                """,
                (tenant_id,),
            )
            return [
                TenantApiKey(
                    key_id=row[0],
                    tenant_id=row[1],
                    name=row[2],
                    key_hash=row[3],
                    prefix=row[4],
                    last_four=row[5],
                    created_at=row[6],
                    revoked_at=row[7],
                    last_used_at=row[8],
                )
                for row in cursor.fetchall()
            ]

    def revoke_api_key(self, tenant_id: str, key_id: str) -> bool:
        now = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE tenant_api_keys
                SET revoked_at = %s
                WHERE key_id = %s AND tenant_id = %s AND revoked_at IS NULL;
                """,
                (now, key_id, tenant_id),
            )
            return cursor.rowcount > 0

    def rotate_api_key(
        self,
        tenant_id: str,
        key_id: str,
        name: Optional[str] = None,
    ) -> Tuple[TenantApiKey, str]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name, prefix FROM tenant_api_keys WHERE key_id = %s AND tenant_id = %s;",
                (key_id, tenant_id),
            )
            row = cursor.fetchone()
            if not row:
                raise KeyNotFoundError(f"Key '{key_id}' does not exist for tenant '{tenant_id}'")
            old_name = row[0]
            old_prefix = row[1]

        self.revoke_api_key(tenant_id, key_id)
        new_name = name.strip() if name and name.strip() else f"{old_name} (Rotated)"
        return self.create_api_key(tenant_id=tenant_id, name=new_name, prefix=old_prefix)

    def touch_key(self, key_id: str) -> None:
        now = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE tenant_api_keys SET last_used_at = %s WHERE key_id = %s;",
                (now, key_id),
            )

