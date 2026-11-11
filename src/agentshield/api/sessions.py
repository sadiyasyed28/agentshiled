"""
Session storage abstraction with HMAC-SHA256 cryptographic token signing,
SQLite-backed revocation tracking, and expiry verification.
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Optional, Protocol, Tuple


@dataclass
class SessionRecord:
    token_hash: str
    user: str
    created_at: float
    expires_at: float
    revoked: bool = False
    tenant_id: str = "default"
    role: str = "tenant_admin"


class SessionStore(Protocol):
    """Protocol for session persistence and revocation storage."""

    def save_session(
        self,
        token_hash: str,
        user: str,
        created_at: float,
        expires_at: float,
        tenant_id: str = "default",
        role: str = "tenant_admin",
    ) -> None:
        """Record an active session token hash."""
        ...

    def is_revoked(self, token_hash: str) -> bool:
        """Check if a session token hash has been explicitly revoked or expired."""
        ...

    def revoke_session(self, token_hash: str) -> bool:
        """Mark a session token hash as revoked."""
        ...

    def cleanup_expired(self) -> int:
        """Purge expired session records."""
        ...

    def get_session(self, token_hash: str) -> Optional[SessionRecord]:
        """Retrieve a session record if found."""
        ...


class SqliteSessionStore:
    """
    Persistent SQLite-backed session store for revocation tracking.
    Stores only the SHA-256 hash of tokens; never raw tokens or admin keys.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        if self.db_path != ":memory:":
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            os.makedirs(db_dir, exist_ok=True)
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    role TEXT NOT NULL DEFAULT 'tenant_admin'
                )
            """)
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(sessions);")
            cols = [c["name"] for c in cursor.fetchall()]
            if "tenant_id" not in cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';")
            if "role" not in cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'tenant_admin';")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id)")
            conn.commit()

    def save_session(
        self,
        token_hash: str,
        user: str,
        created_at: float,
        expires_at: float,
        tenant_id: str = "default",
        role: str = "tenant_admin",
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions (token_hash, user, created_at, expires_at, revoked, tenant_id, role)
                VALUES (?, ?, ?, ?, 0, ?, ?)
                """,
                (token_hash, user, created_at, expires_at, tenant_id, role),
            )
            conn.commit()

    def get_session(self, token_hash: str) -> Optional[SessionRecord]:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT token_hash, user, created_at, expires_at, revoked, tenant_id, role FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            cols = row.keys()
            return SessionRecord(
                token_hash=row["token_hash"],
                user=row["user"],
                created_at=float(row["created_at"]),
                expires_at=float(row["expires_at"]),
                revoked=bool(row["revoked"]),
                tenant_id=row["tenant_id"] if "tenant_id" in cols else "default",
                role=row["role"] if "role" in cols else "tenant_admin",
            )

    def is_revoked(self, token_hash: str) -> bool:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT revoked, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                return False
            if row["revoked"] == 1 or row["expires_at"] < time.time():
                return True
            return False

    def revoke_session(self, token_hash: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
                (token_hash,),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    "INSERT INTO sessions (token_hash, user, created_at, expires_at, revoked) VALUES (?, 'unknown', ?, ?, 1)",
                    (token_hash, time.time(), time.time() + 86400),
                )
            conn.commit()
            return True

    def cleanup_expired(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            conn.commit()
            return cursor.rowcount


class InMemorySessionStore:
    """In-memory session store fallback for testing or ephemeral configurations."""

    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}

    def save_session(
        self,
        token_hash: str,
        user: str,
        created_at: float,
        expires_at: float,
        tenant_id: str = "default",
        role: str = "tenant_admin",
    ) -> None:
        self._sessions[token_hash] = SessionRecord(
            token_hash=token_hash,
            user=user,
            created_at=created_at,
            expires_at=expires_at,
            revoked=False,
            tenant_id=tenant_id,
            role=role,
        )

    def is_revoked(self, token_hash: str) -> bool:
        rec = self._sessions.get(token_hash)
        if not rec:
            return False
        return rec.revoked or rec.expires_at < time.time()

    def revoke_session(self, token_hash: str) -> bool:
        if token_hash in self._sessions:
            self._sessions[token_hash].revoked = True
        else:
            self._sessions[token_hash] = SessionRecord(
                token_hash=token_hash,
                user="unknown",
                created_at=time.time(),
                expires_at=time.time() + 86400,
                revoked=True,
            )
        return True

    def get_session(self, token_hash: str) -> Optional[SessionRecord]:
        return self._sessions.get(token_hash)

    def cleanup_expired(self) -> int:
        now = time.time()
        to_del = [k for k, v in self._sessions.items() if v.expires_at < now]
        for k in to_del:
            del self._sessions[k]
        return len(to_del)


class SessionManager:
    """
    Cryptographic session manager using HMAC-SHA256 signed tokens and SessionStore.

    Token format: base64url(payload).hmac_sha256_hex
    Payload JSON: {"sub": user, "tenant_id": tenant_id, "role": role, "jti": jti, "iat": iat, "exp": exp}
    """

    def __init__(
        self,
        admin_key: str,
        store: SessionStore,
        ttl_seconds: int = 86400,
        session_secret: Optional[str] = None,
    ):
        secret = session_secret or os.environ.get("AGENTSHIELD_SESSION_SECRET") or admin_key
        # Derive dedicated session signing key using HMAC with domain separation
        self.signing_key = hmac.new(b"agentshield-session-v1", secret.encode("utf-8"), hashlib.sha256).digest()
        self.store = store
        self.ttl_seconds = ttl_seconds

    @staticmethod
    def hash_token(token: str) -> str:
        """Hash a token with SHA-256 for secure storage and revocation lookup."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(
        self,
        user: str = "admin",
        user_id: Optional[str] = None,
        tenant_id: str = "default",
        role: str = "tenant_admin",
    ) -> Tuple[str, float]:
        """Generate a cryptographically signed session token and record it in the store."""
        effective_user = user_id or user
        now = time.time()
        expires_at = now + self.ttl_seconds
        jti = uuid.uuid4().hex
        payload = {
            "sub": effective_user,
            "tenant_id": tenant_id,
            "role": role,
            "jti": jti,
            "iat": int(now),
            "exp": int(expires_at),
        }
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        sig = hmac.new(self.signing_key, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        token = f"{payload_b64}.{sig}"
        token_hash = self.hash_token(token)
        self.store.save_session(
            token_hash=token_hash,
            user=effective_user,
            created_at=now,
            expires_at=expires_at,
            tenant_id=tenant_id,
            role=role,
        )
        return token, expires_at

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify the cryptographic signature, expiration, and revocation status of a token.
        Returns payload dict on success or None on failure.
        """
        if not token or "." not in token:
            return None
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts

        expected_sig = hmac.new(self.signing_key, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None

        # Pad base64url string
        rem = len(payload_b64) % 4
        padded = payload_b64 + ("=" * (4 - rem) if rem else "")
        try:
            payload_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            return None

        now = time.time()
        if payload.get("exp", 0) <= now:
            return None

        token_hash = self.hash_token(token)
        if self.store.is_revoked(token_hash):
            return None

        # Ensure multi-tenancy backwards compatibility for legacy tokens
        if "tenant_id" not in payload:
            payload["tenant_id"] = "default"
        if "role" not in payload:
            payload["role"] = "platform_admin" if payload.get("sub") == "admin" else "tenant_admin"

        return payload

    def revoke_token(self, token: str) -> bool:
        """Mark a token as revoked in the session store."""
        if not token:
            return False
        token_hash = self.hash_token(token)
        return self.store.revoke_session(token_hash)

