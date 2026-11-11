"""
Persistent review queue store for AgentShield.
Handles pending, approved, rejected, and expired review states backed by SQLite.
Implements explicit execution states (not_started, executing, succeeded, failed, outcome_unknown),
lease-based worker execution ownership for multi-process safety, and credential sanitization.
"""

from abc import ABC, abstractmethod
from enum import Enum
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from agentshield.models import Decision, DecisionValue, RiskLevel, FrozenDict, normalize_and_freeze, unfreeze_value
from agentshield.audit.store import (
    STANDALONE_AUTH_PATTERN,
    PRIVATE_KEY_PATTERN,
    TEXT_SECRET_PATTERNS,
    redact_sensitive_data,
)
from agentshield.secrets.provider import is_secret_reference

# Targeted credential key pattern: matches actual credential fields while preserving functional keys
# (e.g. device_token, session_token, lookup_key, query_key, idempotency_key are preserved).
CREDENTIAL_KEY_PATTERN = re.compile(
    r"^(?:api[_\s-]?key|apikey|secret|secret[_\s-]?key|password|passwd|pwd|private[_\s-]?key|client[_\s-]?secret|access[_\s-]?token|refresh[_\s-]?token|auth[_\s-]?token|authorization)$",
    re.IGNORECASE,
)


def sanitize_arguments_for_storage(obj: Any) -> Any:
    """Recursively redacts actual credentials and secret values before SQLite persistence,
    while strictly preserving ordinary functional arguments (device_token, lookup_key, session_token, etc.)
    and opaque secret references (secret_ref://...)."""
    if isinstance(obj, dict):
        res = {}
        for k, v in obj.items():
            k_str = str(k)
            if CREDENTIAL_KEY_PATTERN.match(k_str):
                if is_secret_reference(v):
                    res[k_str] = v  # Safe opaque reference; no secret value stored
                else:
                    res[k_str] = "[REDACTED]"
            else:
                res[k_str] = sanitize_arguments_for_storage(v)
        return res
    elif isinstance(obj, list):
        return [sanitize_arguments_for_storage(x) for x in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_arguments_for_storage(x) for x in obj)
    elif isinstance(obj, set):
        return {sanitize_arguments_for_storage(x) for x in obj}
    elif isinstance(obj, str):
        if STANDALONE_AUTH_PATTERN.match(obj) or PRIVATE_KEY_PATTERN.match(obj):
            return "[REDACTED]"
        s = obj
        for pat, rep in TEXT_SECRET_PATTERNS:
            s = pat.sub(rep, s)
        return s
    return obj


class ReviewExecutionState(str, Enum):
    NOT_STARTED = "not_started"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"


class FencingError(RuntimeError):
    """Raised when an execution worker loses its lease or is fenced out by a newer worker."""
    pass


class ReviewStore(ABC):
    """Abstract interface for Review Queue storage."""

    @abstractmethod
    def enqueue_review(
        self,
        review_id: str,
        agent: str,
        tool: str,
        arguments: Any,
        permissions: List[str],
        decision: Decision,
        created_at: float,
        expires_at: float,
        idempotency_key: Optional[str] = None,
        tenant_id: str = "default",
    ) -> None:
        """Enqueues a pending review action."""
        pass

    @abstractmethod
    def get_review(
        self,
        review_id: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieves a review item by review ID."""
        pass

    @abstractmethod
    def get_status(self, review_id: str, now: Optional[float] = None) -> Optional[str]:
        """Returns the current status of a review request ('pending', 'approved', 'rejected', 'expired')."""
        pass

    @abstractmethod
    def get_execution_state(self, review_id: str) -> Optional[str]:
        """Returns the current execution state ('not_started', 'executing', 'succeeded', 'failed', 'outcome_unknown')."""
        pass

    @abstractmethod
    def get_pending_reviews(
        self,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns all unexpired pending review requests."""
        pass

    @abstractmethod
    def expire_pending(self, now: float) -> List[Dict[str, Any]]:
        """Transitions expired pending reviews to 'expired' and returns them."""
        pass

    @abstractmethod
    def reconcile_in_flight(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Reconciles reviews left in 'executing' state whose execution lease has expired.
        Transitions them to 'outcome_unknown'."""
        pass

    @abstractmethod
    def claim_and_approve(
        self,
        review_id: str,
        approver: str,
        now: Optional[float] = None,
        worker_id: Optional[str] = None,
        lease_duration: float = 60.0,
        allow_idempotent_retry: bool = False,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically claims and approves a review. Returns review data if claimed, None if not claimable."""
        pass

    @abstractmethod
    def claim_and_reject(
        self,
        review_id: str,
        reviewer: str,
        reason: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically claims and rejects a pending review. Returns review data if claimed, None if not pending."""
        pass

    @abstractmethod
    def heartbeat(
        self,
        review_id: str,
        worker_id: str,
        extension: float = 60.0,
        now: Optional[float] = None,
    ) -> bool:
        """Extends the execution lease for an active worker currently executing a review.
        Returns True if extended, False if fenced out."""
        pass

    @abstractmethod
    def mark_executed(
        self,
        review_id: str,
        execution_state: str,
        error: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> bool:
        """Updates the execution state of an approved review and clears lease.
        When worker_id is provided, verifies ownership fencing. Returns True if updated, False if fenced out."""
        pass


class SQLiteReviewStore(ReviewStore):
    """Thread-safe and multi-process-safe SQLite review queue implementation."""

    def __init__(self, db_path: Optional[str] = None, timeout: float = 30.0):
        self._lock = threading.Lock()
        self.timeout = timeout
        if db_path:
            self.db_path = db_path
        elif "AGENTSHIELD_REVIEW_DB" in os.environ:
            self.db_path = os.environ["AGENTSHIELD_REVIEW_DB"]
        elif os.environ.get("VERCEL"):
            self.db_path = os.path.join(tempfile.gettempdir(), "agentshield_reviews.db")
        else:
            self.db_path = "agentshield_reviews.db"
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

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS reviews (
                        review_id TEXT PRIMARY KEY,
                        agent TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        arguments TEXT NOT NULL,
                        permissions TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        status TEXT NOT NULL,
                        approver TEXT,
                        reason TEXT,
                        execution_status TEXT NOT NULL DEFAULT 'not_started',
                        error TEXT,
                        idempotency_key TEXT,
                        executed_at REAL,
                        execution_worker_id TEXT,
                        lease_expires_at REAL
                    );
                """)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(reviews);")
                columns = [col["name"] for col in cursor.fetchall()]
                if "idempotency_key" not in columns:
                    cursor.execute("ALTER TABLE reviews ADD COLUMN idempotency_key TEXT;")
                if "executed_at" not in columns:
                    cursor.execute("ALTER TABLE reviews ADD COLUMN executed_at REAL;")
                if "execution_worker_id" not in columns:
                    cursor.execute("ALTER TABLE reviews ADD COLUMN execution_worker_id TEXT;")
                if "lease_expires_at" not in columns:
                    cursor.execute("ALTER TABLE reviews ADD COLUMN lease_expires_at REAL;")
                if "tenant_id" not in columns:
                    cursor.execute("ALTER TABLE reviews ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_expires_at ON reviews(expires_at);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_agent ON reviews(agent);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_exec_status ON reviews(execution_status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_lease ON reviews(execution_status, lease_expires_at);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_reviews_tenant ON reviews(tenant_id, status);")
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

        # Reconcile expired in-flight leases safely (does not affect live active leases)
        self.reconcile_in_flight(now=time.time())

    def _row_to_item(self, row: sqlite3.Row) -> Dict[str, Any]:
        raw_args = json.loads(row["arguments"])
        frozen_args = normalize_and_freeze(raw_args)
        permissions = json.loads(row["permissions"])
        dec_data = json.loads(row["decision"])
        decision = Decision(
            allowed=dec_data["allowed"],
            decision=DecisionValue(dec_data["decision"]),
            reasons=dec_data["reasons"],
            risk_score=float(dec_data["risk_score"]),
            severity=RiskLevel(dec_data["severity"]),
            agent=row["agent"],
            tool=row["tool"],
            arguments=frozen_args,
            trace_id=dec_data.get("trace_id"),
            correlation_id=dec_data.get("correlation_id"),
        )
        row_keys = row.keys()
        exec_state = row["execution_status"]
        return {
            "review_id": row["review_id"],
            "agent": row["agent"],
            "tool": row["tool"],
            "arguments": frozen_args,
            "permissions": permissions,
            "decision": decision,
            "created_at": float(row["created_at"]),
            "expires_at": float(row["expires_at"]),
            "status": row["status"],
            "approver": row["approver"],
            "reason": row["reason"],
            "execution_status": exec_state,  # backward compatibility
            "execution_state": exec_state,   # explicit execution state
            "error": row["error"],
            "idempotency_key": row["idempotency_key"] if "idempotency_key" in row_keys else None,
            "executed_at": float(row["executed_at"]) if "executed_at" in row_keys and row["executed_at"] is not None else None,
            "execution_worker_id": row["execution_worker_id"] if "execution_worker_id" in row_keys else None,
            "lease_expires_at": float(row["lease_expires_at"]) if "lease_expires_at" in row_keys and row["lease_expires_at"] is not None else None,
            "tenant_id": row["tenant_id"] if "tenant_id" in row_keys else "default",
        }

    def enqueue_review(
        self,
        review_id: str,
        agent: str,
        tool: str,
        arguments: Any,
        permissions: List[str],
        decision: Decision,
        created_at: float,
        expires_at: float,
        idempotency_key: Optional[str] = None,
        tenant_id: str = "default",
    ) -> None:
        # Sanitize actual credentials (api_key, password) while preserving functional arguments (device_token, etc.)
        unfrozen = unfreeze_value(arguments) if (hasattr(arguments, "__dict__") or isinstance(arguments, (dict, list))) else arguments
        cleaned_args = sanitize_arguments_for_storage(unfrozen or {})
        args_json = json.dumps(cleaned_args)
        perm_json = json.dumps(permissions or [])
        dec_dict = {
            "allowed": decision.allowed,
            "decision": decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision),
            "reasons": decision.reasons,
            "risk_score": float(decision.risk_score),
            "severity": decision.severity.value if hasattr(decision.severity, "value") else str(decision.severity),
            "trace_id": getattr(decision, "trace_id", None),
            "correlation_id": getattr(decision, "correlation_id", None),
        }
        dec_json = json.dumps(dec_dict)

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO reviews (
                        review_id, agent, tool, arguments, permissions, decision,
                        created_at, expires_at, status, execution_status, idempotency_key, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
                    """,
                    (
                        review_id,
                        agent,
                        tool,
                        args_json,
                        perm_json,
                        dec_json,
                        created_at,
                        expires_at,
                        ReviewExecutionState.NOT_STARTED.value,
                        idempotency_key,
                        tenant_id,
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

    def expire_pending(self, now: float) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT review_id, agent, tool, arguments, permissions, decision,
                           created_at, expires_at, status, approver, reason, execution_status,
                           error, idempotency_key, executed_at, execution_worker_id, lease_expires_at
                    FROM reviews
                    WHERE status = 'pending' AND expires_at <= ?
                    """,
                    (now,),
                )
                rows = cursor.fetchall()
                if rows:
                    cursor.execute(
                        "UPDATE reviews SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?",
                        (now,),
                    )
                conn.commit()
                return [self._row_to_item(r) for r in rows]
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def reconcile_in_flight(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Safely reconciles reviews left in 'executing' state whose execution lease has expired.
        Transitions them to 'outcome_unknown' without disturbing active live leases."""
        if now is None:
            now = time.time()

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT review_id, agent, tool, arguments, permissions, decision,
                           created_at, expires_at, status, approver, reason, execution_status,
                           error, idempotency_key, executed_at, execution_worker_id, lease_expires_at
                    FROM reviews
                    WHERE status = 'approved'
                      AND execution_status = ?
                      AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                    """,
                    (ReviewExecutionState.EXECUTING.value, now),
                )
                rows = cursor.fetchall()
                if rows:
                    cursor.execute(
                        """
                        UPDATE reviews
                        SET execution_status = ?
                        WHERE status = 'approved'
                          AND execution_status = ?
                          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                        """,
                        (ReviewExecutionState.OUTCOME_UNKNOWN.value, ReviewExecutionState.EXECUTING.value, now),
                    )
                conn.commit()
                return [self._row_to_item(r) for r in rows]
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def get_review(
        self,
        review_id: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if now is None:
            now = time.time()
        self.expire_pending(now)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute(
                        """
                        SELECT review_id, agent, tool, arguments, permissions, decision,
                               created_at, expires_at, status, approver, reason, execution_status,
                               error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                        FROM reviews
                        WHERE review_id = ? AND tenant_id = ?
                        """,
                        (review_id, tenant_id),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT review_id, agent, tool, arguments, permissions, decision,
                               created_at, expires_at, status, approver, reason, execution_status,
                               error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                        FROM reviews
                        WHERE review_id = ?
                        """,
                        (review_id,),
                    )
                row = cursor.fetchone()
                return self._row_to_item(row) if row else None
            finally:
                self._close_connection(conn)

    def get_status(self, review_id: str, now: Optional[float] = None) -> Optional[str]:
        if now is None:
            now = time.time()
        self.expire_pending(now)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT status FROM reviews WHERE review_id = ?", (review_id,))
                row = cursor.fetchone()
                return row["status"] if row else None
            finally:
                self._close_connection(conn)

    def get_execution_state(self, review_id: str) -> Optional[str]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT execution_status FROM reviews WHERE review_id = ?", (review_id,))
                row = cursor.fetchone()
                return row["execution_status"] if row else None
            finally:
                self._close_connection(conn)

    def get_pending_reviews(
        self,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if now is None:
            now = time.time()
        self.expire_pending(now)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if tenant_id is not None:
                    cursor.execute(
                        """
                        SELECT review_id, agent, tool, arguments, permissions, decision,
                               created_at, expires_at, status, approver, reason, execution_status,
                               error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                        FROM reviews
                        WHERE status = 'pending' AND tenant_id = ?
                        ORDER BY created_at ASC
                        """,
                        (tenant_id,),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT review_id, agent, tool, arguments, permissions, decision,
                               created_at, expires_at, status, approver, reason, execution_status,
                               error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                        FROM reviews
                        WHERE status = 'pending'
                        ORDER BY created_at ASC
                        """
                    )
                rows = cursor.fetchall()
                return [self._row_to_item(r) for r in rows]
            finally:
                self._close_connection(conn)

    def claim_and_approve(
        self,
        review_id: str,
        approver: str,
        now: Optional[float] = None,
        worker_id: Optional[str] = None,
        lease_duration: float = 60.0,
        allow_idempotent_retry: bool = False,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if now is None:
            now = time.time()
        worker_id = worker_id or f"worker_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        lease_expires = now + lease_duration

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT review_id, agent, tool, arguments, permissions, decision,
                           created_at, expires_at, status, approver, reason, execution_status,
                           error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                    FROM reviews
                    WHERE review_id = ?
                    """,
                    (review_id,),
                )
                row = cursor.fetchone()
                if not row:
                    conn.commit()
                    return None

                # Tenant boundary enforcement: prevent cross-tenant approval (IDOR)
                if tenant_id is not None:
                    row_tenant = row["tenant_id"] if "tenant_id" in row.keys() else "default"
                    if row_tenant != tenant_id:
                        conn.commit()
                        return None

                status = row["status"]
                exec_state = row["execution_status"]

                # Case 1: Standard pending review transition
                if status == "pending" and exec_state in (
                    ReviewExecutionState.NOT_STARTED.value,
                    "not_executed",
                ):
                    if row["expires_at"] <= now:
                        cursor.execute("UPDATE reviews SET status = 'expired' WHERE review_id = ?", (review_id,))
                        conn.commit()
                        return None

                    cursor.execute(
                        """
                        UPDATE reviews
                        SET status = 'approved', approver = ?, execution_status = ?, executed_at = ?,
                            execution_worker_id = ?, lease_expires_at = ?
                        WHERE review_id = ? AND status = 'pending'
                        """,
                        (approver, ReviewExecutionState.EXECUTING.value, now, worker_id, lease_expires, review_id),
                    )
                    if cursor.rowcount != 1:
                        conn.commit()
                        return None

                    conn.commit()
                    item = self._row_to_item(row)
                    item["execution_state"] = ReviewExecutionState.EXECUTING.value
                    item["execution_status"] = ReviewExecutionState.EXECUTING.value
                    item["execution_worker_id"] = worker_id
                    item["lease_expires_at"] = lease_expires
                    return item

                # Case 2: Idempotent or read-only retry of crash-recovered outcome_unknown
                elif (
                    status == "approved"
                    and exec_state == ReviewExecutionState.OUTCOME_UNKNOWN.value
                    and allow_idempotent_retry
                ):
                    cursor.execute(
                        """
                        UPDATE reviews
                        SET approver = ?, execution_status = ?, executed_at = ?,
                            execution_worker_id = ?, lease_expires_at = ?
                        WHERE review_id = ? AND execution_status = ?
                        """,
                        (approver, ReviewExecutionState.EXECUTING.value, now, worker_id, lease_expires, review_id, ReviewExecutionState.OUTCOME_UNKNOWN.value),
                    )
                    if cursor.rowcount != 1:
                        conn.commit()
                        return None

                    conn.commit()
                    item = self._row_to_item(row)
                    item["execution_state"] = ReviewExecutionState.EXECUTING.value
                    item["execution_status"] = ReviewExecutionState.EXECUTING.value
                    item["execution_worker_id"] = worker_id
                    item["lease_expires_at"] = lease_expires
                    return item

                # All other states (already executing with live lease, succeeded, failed, or non-idempotent outcome_unknown): reject claim
                conn.commit()
                return None
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def claim_and_reject(
        self,
        review_id: str,
        reviewer: str,
        reason: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if now is None:
            now = time.time()

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT review_id, agent, tool, arguments, permissions, decision,
                           created_at, expires_at, status, approver, reason, execution_status,
                           error, idempotency_key, executed_at, execution_worker_id, lease_expires_at, tenant_id
                    FROM reviews
                    WHERE review_id = ?
                    """,
                    (review_id,),
                )
                row = cursor.fetchone()
                if not row:
                    conn.commit()
                    return None

                # Tenant boundary enforcement: prevent cross-tenant rejection
                if tenant_id is not None:
                    row_tenant = row["tenant_id"] if "tenant_id" in row.keys() else "default"
                    if row_tenant != tenant_id:
                        conn.commit()
                        return None

                if row["status"] != "pending":
                    conn.commit()
                    return None

                if row["expires_at"] <= now:
                    cursor.execute("UPDATE reviews SET status = 'expired' WHERE review_id = ?", (review_id,))
                    conn.commit()
                    return None

                # Atomically reject
                cursor.execute(
                    """
                    UPDATE reviews
                    SET status = 'rejected', approver = ?, reason = ?
                    WHERE review_id = ? AND status = 'pending'
                    """,
                    (reviewer, reason, review_id),
                )
                if cursor.rowcount != 1:
                    conn.commit()
                    return None

                conn.commit()
                return self._row_to_item(row)
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def heartbeat(
        self,
        review_id: str,
        worker_id: str,
        extension: float = 60.0,
        now: Optional[float] = None,
    ) -> bool:
        """Extends the execution lease for an active worker currently executing a review.
        Returns True if lease was extended, or False if the worker was fenced out."""
        if now is None:
            now = time.time()
        new_expires = now + extension

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    """
                    UPDATE reviews
                    SET lease_expires_at = ?
                    WHERE review_id = ?
                      AND execution_worker_id = ?
                      AND execution_status = ?
                    """,
                    (new_expires, review_id, worker_id, ReviewExecutionState.EXECUTING.value),
                )
                updated = (cursor.rowcount == 1)
                conn.commit()
                return updated
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

    def mark_executed(
        self,
        review_id: str,
        execution_state: str,
        error: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> bool:
        """Updates the execution state of an approved review and clears lease.
        When worker_id is provided, verifies ownership fencing: fails if the worker lost its lease.
        Returns True if updated, False if fenced out.
        """
        cleaned_error = redact_sensitive_data(error) if error is not None else None
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                if worker_id is not None:
                    cursor.execute(
                        """
                        UPDATE reviews
                        SET execution_status = ?, error = ?, lease_expires_at = NULL
                        WHERE review_id = ?
                          AND execution_worker_id = ?
                          AND execution_status = ?
                        """,
                        (execution_state, cleaned_error, review_id, worker_id, ReviewExecutionState.EXECUTING.value),
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE reviews
                        SET execution_status = ?, error = ?, lease_expires_at = NULL
                        WHERE review_id = ?
                        """,
                        (execution_state, cleaned_error, review_id),
                    )
                updated = (cursor.rowcount == 1)
                conn.commit()
                return updated
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)
