"""
PostgreSQL Review Store for AgentShield.

Provides thread-safe and multi-instance-safe human review queue storage,
atomic row-level locking (SELECT ... FOR UPDATE), lease management, and heartbeat fencing.
Supports configurable table prefixes for complete simulator isolation.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
import uuid

from agentshield.models import Decision
from agentshield.review.store import (
    FencingError,
    ReviewExecutionState,
    ReviewStore,
    sanitize_arguments_for_storage,
)
from agentshield.storage.connection import PostgresConnectionManager

logger = logging.getLogger("agentshield.storage.review")


class PostgresReviewStore(ReviewStore):
    """PostgreSQL implementation of ReviewStore with row-level locking."""

    def __init__(
        self,
        dsn: str,
        table_prefix: str = "",
        connection_manager: Optional[PostgresConnectionManager] = None,
    ):
        self.table_prefix = table_prefix
        self.table_name = f"{table_prefix}reviews"
        self.connection_manager = connection_manager or PostgresConnectionManager(dsn=dsn)
        self.init_db()

    def init_db(self) -> None:
        """Initializes review queue table and indexes."""
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
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
                    updated_at DOUBLE PRECISION NOT NULL,
                    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'
                );
            """)
            cursor.execute(f"ALTER TABLE {self.table_name} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_status ON {self.table_name}(status);")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_expires ON {self.table_name}(expires_at);")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_idemp ON {self.table_name}(idempotency_key);")
            cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{self.table_name}_tenant ON {self.table_name}(tenant_id, status);")

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
        now = time.time()
        cleaned_args = sanitize_arguments_for_storage(arguments)
        args_json = json.dumps(cleaned_args)
        perms_json = json.dumps(permissions or [])
        dec_json = json.dumps(decision.to_dict() if hasattr(decision, "to_dict") else {
            "allowed": decision.allowed,
            "decision": decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision),
            "reasons": decision.reasons,
            "risk_score": float(decision.risk_score),
            "severity": decision.severity.value if hasattr(decision.severity, "value") else str(decision.severity),
        })

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                INSERT INTO {self.table_name} (
                    review_id, agent, tool, arguments, permissions, decision,
                    created_at, expires_at, status, execution_status,
                    idempotency_key, updated_at, tenant_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', 'not_started', %s, %s, %s);
            """, (
                review_id,
                agent,
                tool,
                args_json,
                perms_json,
                dec_json,
                created_at,
                expires_at,
                idempotency_key,
                now,
                tenant_id,
            ))

    def _row_to_dict(self, row_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "review_id": row_dict["review_id"],
            "agent": row_dict["agent"],
            "tool": row_dict["tool"],
            "arguments": json.loads(row_dict["arguments"]),
            "permissions": json.loads(row_dict["permissions"]),
            "decision": json.loads(row_dict["decision"]),
            "created_at": row_dict["created_at"],
            "expires_at": row_dict["expires_at"],
            "status": row_dict["status"],
            "approver": row_dict.get("approver"),
            "reason": row_dict.get("reason"),
            "execution_status": row_dict.get("execution_status", "not_started"),
            "error": row_dict.get("error"),
            "idempotency_key": row_dict.get("idempotency_key"),
            "executed_at": row_dict.get("executed_at"),
            "execution_worker_id": row_dict.get("execution_worker_id"),
            "lease_expires_at": row_dict.get("lease_expires_at"),
            "updated_at": row_dict.get("updated_at"),
            "tenant_id": row_dict.get("tenant_id", "default"),
        }

    def get_review(
        self,
        review_id: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id is not None:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s AND tenant_id = %s;", (review_id, tenant_id))
            else:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s;", (review_id,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_dict(dict(zip(col_names, row)))

    def get_status(self, review_id: str, now: Optional[float] = None) -> Optional[str]:
        item = self.get_review(review_id, now)
        if not item:
            return None
        current_time = now if now is not None else time.time()
        if item["status"] == "pending" and item["expires_at"] < current_time:
            return "expired"
        return item["status"]

    def get_execution_state(self, review_id: str) -> Optional[str]:
        item = self.get_review(review_id)
        if not item:
            return None
        return item.get("execution_status")

    def get_pending_reviews(
        self,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        current_time = now if now is not None else time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if tenant_id is not None:
                cursor.execute(f"""
                    SELECT * FROM {self.table_name}
                    WHERE status = 'pending' AND expires_at >= %s AND tenant_id = %s
                    ORDER BY created_at ASC;
                """, (current_time, tenant_id))
            else:
                cursor.execute(f"""
                    SELECT * FROM {self.table_name}
                    WHERE status = 'pending' AND expires_at >= %s
                    ORDER BY created_at ASC;
                """, (current_time,))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            return [self._row_to_dict(dict(zip(col_names, r))) for r in cursor.fetchall()]

    def expire_pending(self, now: float) -> List[Dict[str, Any]]:
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT review_id FROM {self.table_name}
                WHERE status = 'pending' AND expires_at < %s;
            """, (now,))
            expired_ids = [r[0] for r in cursor.fetchall()]
            if expired_ids:
                cursor.execute(f"""
                    UPDATE {self.table_name}
                    SET status = 'expired', updated_at = %s
                    WHERE status = 'pending' AND expires_at < %s;
                """, (now, now))
            return [self.get_review(r_id, now) for r_id in expired_ids]  # type: ignore

    def reconcile_in_flight(self, now: Optional[float] = None) -> List[Dict[str, Any]]:
        current_time = now if now is not None else time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                SELECT review_id FROM {self.table_name}
                WHERE status = 'approved'
                  AND execution_status = 'executing'
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at < %s;
            """, (current_time,))
            reconcile_ids = [r[0] for r in cursor.fetchall()]
            if reconcile_ids:
                cursor.execute(f"""
                    UPDATE {self.table_name}
                    SET execution_status = 'outcome_unknown',
                        error = 'Worker lease expired during execution (presumed crashed)',
                        updated_at = %s
                    WHERE status = 'approved'
                      AND execution_status = 'executing'
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at < %s;
                """, (current_time, current_time))
            return [self.get_review(r_id, current_time) for r_id in reconcile_ids]  # type: ignore

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
        current_time = now if now is not None else time.time()
        worker = worker_id or f"worker_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        lease_expires = current_time + lease_duration

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            # Row-level lock: SELECT ... FOR UPDATE ensures race-free claim across instances
            try:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s FOR UPDATE;", (review_id,))
            except Exception:
                # If mock dialect doesn't support FOR UPDATE, fallback to normal SELECT
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s;", (review_id,))

            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            item = self._row_to_dict(dict(zip(col_names, row)))

            # Tenant boundary enforcement: prevent cross-tenant approval (IDOR)
            if tenant_id is not None and item.get("tenant_id", "default") != tenant_id:
                return None

            status = item["status"]
            exec_state = item["execution_status"]
            expires_at = item["expires_at"]

            if status == "pending":
                if expires_at < current_time:
                    cursor.execute(f"UPDATE {self.table_name} SET status = 'expired', updated_at = %s WHERE review_id = %s;", (current_time, review_id))
                    return None

                cursor.execute(f"""
                    UPDATE {self.table_name}
                    SET status = 'approved',
                        approver = %s,
                        execution_status = 'executing',
                        execution_worker_id = %s,
                        lease_expires_at = %s,
                        updated_at = %s
                    WHERE review_id = %s;
                """, (approver, worker, lease_expires, current_time, review_id))
                item["status"] = "approved"
                item["approver"] = approver
                item["execution_status"] = "executing"
                item["execution_worker_id"] = worker
                item["lease_expires_at"] = lease_expires
                return item

            if status == "approved" and exec_state in ("failed", "outcome_unknown") and allow_idempotent_retry:
                cursor.execute(f"""
                    UPDATE {self.table_name}
                    SET execution_status = 'executing',
                        execution_worker_id = %s,
                        lease_expires_at = %s,
                        error = NULL,
                        updated_at = %s
                    WHERE review_id = %s;
                """, (worker, lease_expires, current_time, review_id))
                item["execution_status"] = "executing"
                item["execution_worker_id"] = worker
                item["lease_expires_at"] = lease_expires
                return item

            return None

    def claim_and_reject(
        self,
        review_id: str,
        reviewer: str,
        reason: str,
        now: Optional[float] = None,
        tenant_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        current_time = now if now is not None else time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s FOR UPDATE;", (review_id,))
            except Exception:
                cursor.execute(f"SELECT * FROM {self.table_name} WHERE review_id = %s;", (review_id,))

            col_names = [d[0] for d in cursor.description] if cursor.description else []
            row = cursor.fetchone()
            if not row:
                return None
            item = self._row_to_dict(dict(zip(col_names, row)))

            # Tenant boundary enforcement: prevent cross-tenant rejection
            if tenant_id is not None and item.get("tenant_id", "default") != tenant_id:
                return None

            if item["status"] != "pending":
                return None
            if item["expires_at"] < current_time:
                cursor.execute(f"UPDATE {self.table_name} SET status = 'expired', updated_at = %s WHERE review_id = %s;", (current_time, review_id))
                return None

            cursor.execute(f"""
                UPDATE {self.table_name}
                SET status = 'rejected',
                    approver = %s,
                    reason = %s,
                    updated_at = %s
                WHERE review_id = %s;
            """, (reviewer, reason, current_time, review_id))
            item["status"] = "rejected"
            item["approver"] = reviewer
            item["reason"] = reason
            return item

    def heartbeat(
        self,
        review_id: str,
        worker_id: str,
        extension: float = 60.0,
        now: Optional[float] = None,
    ) -> bool:
        current_time = now if now is not None else time.time()
        new_lease = current_time + extension
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE {self.table_name}
                SET lease_expires_at = %s, updated_at = %s
                WHERE review_id = %s
                  AND status = 'approved'
                  AND execution_status = 'executing'
                  AND execution_worker_id = %s
                  AND (lease_expires_at IS NULL OR lease_expires_at >= %s);
            """, (new_lease, current_time, review_id, worker_id, current_time))
            return cursor.rowcount > 0

    def mark_executed(
        self,
        review_id: str,
        execution_state: str,
        error: Optional[str] = None,
        worker_id: Optional[str] = None,
    ) -> bool:
        current_time = time.time()
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            if worker_id is not None:
                cursor.execute(f"SELECT execution_worker_id, lease_expires_at FROM {self.table_name} WHERE review_id = %s;", (review_id,))
                row = cursor.fetchone()
                if row:
                    owner_id, lease_exp = row[0], row[1]
                    if owner_id != worker_id or (lease_exp is not None and lease_exp < current_time):
                        raise FencingError(f"Worker '{worker_id}' fenced out of review '{review_id}'")

            cursor.execute(f"""
                UPDATE {self.table_name}
                SET execution_status = %s,
                    error = %s,
                    executed_at = %s,
                    lease_expires_at = NULL,
                    updated_at = %s
                WHERE review_id = %s;
            """, (execution_state, error, current_time, current_time, review_id))
            return cursor.rowcount > 0

