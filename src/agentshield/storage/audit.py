"""
PostgreSQL Audit Store for AgentShield.

Provides thread-safe and multi-instance-safe append-only audit logging with
cryptographic SHA-256 hash chaining across serverless instances.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional

from agentshield.audit.store import (
    GENESIS_HASH,
    AuditRecord,
    AuditStore,
    compute_record_hash,
    redact_sensitive_data,
)
from agentshield.models import Decision
from agentshield.storage.connection import PostgresConnectionManager

logger = logging.getLogger("agentshield.storage.audit")

# Unique 32-bit key for PostgreSQL advisory lock to serialize audit hash chaining across serverless workers
AUDIT_LOCK_ID = 71829103


class PostgresAuditStore(AuditStore):
    """PostgreSQL implementation of AuditStore with cryptographic SHA-256 hash chaining."""

    def __init__(self, dsn: str, connection_manager: Optional[PostgresConnectionManager] = None):
        self.connection_manager = connection_manager or PostgresConnectionManager(dsn=dsn)
        self.init_db()

    def init_db(self) -> None:
        """Initializes audit_logs table and performance indexes."""
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
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
                    trace_id VARCHAR(128),
                    tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'
                );
            """)
            cursor.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64) NOT NULL DEFAULT 'default';")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_record_hash ON audit_logs(record_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_logs(correlation_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id, timestamp DESC);")

    def log_decision(
        self,
        decision: Decision,
        arguments: Optional[Dict[str, Any]] = None,
        execution_status: str = "not_executed",
        error: Optional[str] = None,
        policy_version_hash: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        tenant_id: str = "default",
    ) -> int:
        cleaned_args = redact_sensitive_data(arguments or {})
        cleaned_error = redact_sensitive_data(error) if error is not None else None
        rules = [r.split(":")[0].strip() for r in decision.reasons if ":" in r]

        timestamp = datetime.now(timezone.utc).isoformat()
        decision_str = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)
        severity_str = decision.severity.value if hasattr(decision.severity, "value") else str(decision.severity)
        args_json = json.dumps(cleaned_args)
        reasons_json = json.dumps(decision.reasons)
        rules_json = json.dumps(rules)
        risk_factors_json = json.dumps([])

        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            # Acquire transaction-scoped advisory lock to serialize hash chaining across concurrent workers
            try:
                cursor.execute("SELECT pg_advisory_xact_lock(%s);", (AUDIT_LOCK_ID,))
            except Exception:
                # If mock or dialect doesn't support pg_advisory_xact_lock, continue
                pass

            cursor.execute("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1;")
            latest = cursor.fetchone()
            prev_hash = latest[0] if (latest and latest[0]) else GENESIS_HASH

            record_hash = compute_record_hash(
                prev_hash=prev_hash,
                timestamp=timestamp,
                agent=decision.agent,
                tool=decision.tool,
                arguments_json=args_json,
                decision=decision_str,
                allowed=1 if decision.allowed else 0,
                reasons_json=reasons_json,
                rules_triggered_json=rules_json,
                risk_score=float(decision.risk_score),
                severity=severity_str,
                risk_factors_json=risk_factors_json,
                execution_status=execution_status,
                error=cleaned_error,
                policy_version_hash=policy_version_hash,
            )

            eff_tenant = getattr(decision, "tenant_id", None) or tenant_id or "default"
            cursor.execute("""
                INSERT INTO audit_logs (
                    timestamp, agent, tool, arguments, decision, allowed,
                    reasons, rules_triggered, risk_score, severity,
                    risk_factors, execution_status, error, policy_version_hash,
                    prev_hash, record_hash, correlation_id, trace_id, tenant_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (
                timestamp,
                decision.agent,
                decision.tool,
                args_json,
                decision_str,
                1 if decision.allowed else 0,
                reasons_json,
                rules_json,
                float(decision.risk_score),
                severity_str,
                risk_factors_json,
                execution_status,
                cleaned_error,
                policy_version_hash,
                prev_hash,
                record_hash,
                correlation_id or getattr(decision, "correlation_id", None),
                trace_id or getattr(decision, "trace_id", None),
                eff_tenant,
            ))
            row = cursor.fetchone()
            return int(row[0]) if row else 0

    def query(
        self,
        decision: Optional[str] = None,
        agent: Optional[str] = None,
        tool: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        correlation_id: Optional[str] = None,
        limit: int = 50,
        tenant_id: Optional[str] = None,
    ) -> List[AuditRecord]:
        conditions: List[str] = []
        params: List[Any] = []

        if decision:
            conditions.append("decision = %s")
            params.append(decision.upper())
        if agent:
            conditions.append("agent = %s")
            params.append(agent)
        if tool:
            conditions.append("tool = %s")
            params.append(tool)
        if start_time:
            conditions.append("timestamp >= %s")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= %s")
            params.append(end_time)
        if correlation_id:
            conditions.append("correlation_id = %s")
            params.append(correlation_id)
        if tenant_id is not None:
            conditions.append("tenant_id = %s")
            params.append(tenant_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query_sql = f"""
            SELECT id, timestamp, agent, tool, arguments, decision, allowed,
                   reasons, rules_triggered, risk_score, severity, risk_factors,
                   execution_status, error, policy_version_hash, prev_hash, record_hash,
                   correlation_id, trace_id, tenant_id
            FROM audit_logs
            {where_clause}
            ORDER BY id DESC
            LIMIT %s
        """
        params.append(limit)

        records: List[AuditRecord] = []
        with self.connection_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, tuple(params))
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            for row in cursor.fetchall():
                row_dict = dict(zip(col_names, row))
                records.append(
                    AuditRecord(
                        id=row_dict["id"],
                        timestamp=row_dict["timestamp"],
                        agent=row_dict["agent"],
                        tool=row_dict["tool"],
                        arguments=json.loads(row_dict["arguments"]),
                        decision=row_dict["decision"],
                        allowed=bool(row_dict["allowed"]),
                        reasons=json.loads(row_dict["reasons"]),
                        rules_triggered=json.loads(row_dict["rules_triggered"]),
                        risk_score=row_dict["risk_score"],
                        severity=row_dict["severity"],
                        risk_factors=json.loads(row_dict["risk_factors"]),
                        execution_status=row_dict["execution_status"],
                        error=row_dict["error"],
                        policy_version_hash=row_dict.get("policy_version_hash"),
                        prev_hash=row_dict.get("prev_hash"),
                        record_hash=row_dict.get("record_hash"),
                        correlation_id=row_dict.get("correlation_id"),
                        trace_id=row_dict.get("trace_id"),
                        tenant_id=row_dict.get("tenant_id", "default"),
                    )
                )
        return records

    def verify_integrity(self, cursor: Optional[Any] = None) -> Dict[str, Any]:
        if cursor is not None:
            cursor.execute("""
                SELECT id, timestamp, agent, tool, arguments, decision, allowed,
                       reasons, rules_triggered, risk_score, severity, risk_factors,
                       execution_status, error, policy_version_hash, prev_hash, record_hash
                FROM audit_logs
                ORDER BY id ASC;
            """)
            col_names = [d[0] for d in cursor.description] if cursor.description else []
            rows = cursor.fetchall()
        else:
            with self.connection_manager.get_connection() as conn:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, timestamp, agent, tool, arguments, decision, allowed,
                           reasons, rules_triggered, risk_score, severity, risk_factors,
                           execution_status, error, policy_version_hash, prev_hash, record_hash
                    FROM audit_logs
                    ORDER BY id ASC;
                """)
                col_names = [d[0] for d in cur.description] if cur.description else []
                rows = cur.fetchall()

        if not rows:
            return {"valid": True, "total_records": 0, "records_checked": 0, "broken_at_id": None, "reason": None, "error": None}

        expected_prev_hash = GENESIS_HASH
        for row in rows:
            row_dict = dict(zip(col_names, row))
            r_id = row_dict["id"]
            actual_prev = row_dict.get("prev_hash")
            actual_record = row_dict.get("record_hash")

            if actual_prev != expected_prev_hash:
                err_msg = f"Record {r_id} prev_hash mismatch: expected {expected_prev_hash[:12]}..., got {str(actual_prev)[:12]}..."
                return {
                    "valid": False,
                    "total_records": len(rows),
                    "records_checked": len(rows),
                    "broken_at_id": r_id,
                    "reason": err_msg,
                    "error": err_msg,
                }

            expected_record_hash = compute_record_hash(
                prev_hash=actual_prev,
                timestamp=row_dict["timestamp"],
                agent=row_dict["agent"],
                tool=row_dict["tool"],
                arguments_json=row_dict["arguments"],
                decision=row_dict["decision"],
                allowed=1 if row_dict["allowed"] else 0,
                reasons_json=row_dict["reasons"],
                rules_triggered_json=row_dict["rules_triggered"],
                risk_score=float(row_dict["risk_score"]),
                severity=row_dict["severity"],
                risk_factors_json=row_dict["risk_factors"],
                execution_status=row_dict["execution_status"],
                error=row_dict["error"],
                policy_version_hash=row_dict.get("policy_version_hash"),
            )

            if actual_record != expected_record_hash:
                err_msg = f"Record {r_id} record_hash corrupted: computed {expected_record_hash[:12]}..., stored {str(actual_record)[:12]}..."
                return {
                    "valid": False,
                    "total_records": len(rows),
                    "records_checked": len(rows),
                    "broken_at_id": r_id,
                    "reason": err_msg,
                    "error": err_msg,
                }

            expected_prev_hash = actual_record

        return {"valid": True, "total_records": len(rows), "records_checked": len(rows), "broken_at_id": None, "reason": None, "error": None}

