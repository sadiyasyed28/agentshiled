"""
Audit storage interface and SQLite implementation for AgentShield.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import threading
from typing import Any, Dict, List, Optional
from agentshield.models import Decision, DecisionValue, RiskLevel

GENESIS_HASH: str = "0" * 64

# Sensitive key patterns for automatic redaction in dictionary keys
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|[_\s-])(?:api[_\s-]?key|password|passwd|pwd|secret|token|credential|bearer|private[_\s-]?key|auth(?:orization)?|auth[_\s-]?token|auth[_\s-]?key)(?:$|[_\s-])",
    re.IGNORECASE
)

# Standalone authorization header / token strings
STANDALONE_AUTH_PATTERN = re.compile(
    r"^\s*(?:bearer|basic)\s+[^\s]+\s*$",
    re.IGNORECASE
)

# Private key block
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----"
)

# Text secret patterns embedded in free text
TEXT_SECRET_PATTERNS = [
    (PRIVATE_KEY_PATTERN, "[REDACTED PRIVATE KEY]"),
    # URL credentials: e.g. https://user:pass@domain.com
    (re.compile(r"://([^:\s/]+):([^@\s/]+)@"), r"://\1:[REDACTED]@"),
    # Bearer tokens in text
    (re.compile(r"\bbearer\s+[a-zA-Z0-9_\-\.\~+/=]{8,}", re.IGNORECASE), "Bearer [REDACTED]"),
    # Basic auth in text
    (re.compile(r"\bbasic\s+[a-zA-Z0-9+/=]{10,}", re.IGNORECASE), "Basic [REDACTED]"),
    # OpenAI & API key formats: sk-..., sk-test..., sk-live..., sk-proj-...
    (re.compile(r"\bsk-(?:test|live|proj-)?[a-zA-Z0-9_\-]{10,}"), "[REDACTED]"),
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    # Google API Key
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{30,36}\b"), "[REDACTED]"),
    # GitHub Tokens
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"), "[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "[REDACTED]"),
    # Slack Tokens
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "[REDACTED]"),
    # URL query parameter secrets: e.g. ?token=xyz&foo=bar, ?api_key=xyz, ?secret=xyz
    (re.compile(r"([?&](?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd|client[_-]?secret)=)(['\"]?)([^\s,;\"'&]+)(['\"]?)", re.IGNORECASE), r"\1\2[REDACTED]\4"),
    # Key-value secret assignments in text, e.g. password=secret or api_key: xyz or password='xyz'
    (re.compile(r"""\b(api[_\s-]?key|password|passwd|pwd|secret[_\s-]?key|access[_\s-]?token|auth[_\s-]?token)(\s*[:=]\s*)(['"]?)([^\s,;"'&]+)(['"]?)""", re.IGNORECASE), r"\1\2\3[REDACTED]\5"),
]

def redact_text_secrets(text: str) -> str:
    """Redacts secrets embedded within free text while preserving surrounding useful context."""
    if STANDALONE_AUTH_PATTERN.match(text):
        return "[REDACTED]"
    result = text
    for pat, rep in TEXT_SECRET_PATTERNS:
        result = pat.sub(rep, result)
    return result

def redact_sensitive_data(obj: Any) -> Any:
    """Recursively redacts sensitive keys and values in arguments without mutating input objects."""
    if isinstance(obj, dict):
        redacted = {}
        for k, v in obj.items():
            key_str = str(k)
            if SENSITIVE_KEY_PATTERN.search(key_str):
                if isinstance(v, str) and (v.startswith("secret_ref://") or v.startswith("vault://") or v.startswith("env://")):
                    redacted[key_str] = v
                else:
                    redacted[key_str] = "[REDACTED]"
            else:
                redacted[key_str] = redact_sensitive_data(v)
        return redacted
    elif isinstance(obj, list):
        return [redact_sensitive_data(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(redact_sensitive_data(item) for item in obj)
    elif isinstance(obj, set):
        return {redact_sensitive_data(item) for item in obj}
    elif isinstance(obj, str):
        return redact_text_secrets(obj)
    return obj

def compute_record_hash(
    prev_hash: str,
    timestamp: str,
    agent: str,
    tool: str,
    arguments_json: str,
    decision: str,
    allowed: int,
    reasons_json: str,
    rules_triggered_json: str,
    risk_score: float,
    severity: str,
    risk_factors_json: str,
    execution_status: str,
    error: Optional[str],
    policy_version_hash: Optional[str],
) -> str:
    """Computes a deterministic SHA-256 digest of an audit record and its predecessor link."""
    payload = {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "agent": agent,
        "tool": tool,
        "arguments": arguments_json,
        "decision": decision,
        "allowed": allowed,
        "reasons": reasons_json,
        "rules_triggered": rules_triggered_json,
        "risk_score": f"{float(risk_score):.4f}",
        "severity": severity,
        "risk_factors": risk_factors_json,
        "execution_status": execution_status,
        "error": error or "",
        "policy_version_hash": policy_version_hash or "",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

@dataclass
class AuditRecord:
    id: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent: str = "unknown"
    tool: str = "unknown"
    arguments: Dict[str, Any] = field(default_factory=dict)
    decision: str = "BLOCK"
    allowed: bool = False
    reasons: List[str] = field(default_factory=list)
    rules_triggered: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "LOW"
    risk_factors: List[str] = field(default_factory=list)
    execution_status: str = "not_executed"
    error: Optional[str] = None
    policy_version_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None
    tenant_id: str = "default"

class AuditStore(ABC):
    """Abstract Audit Storage interface (allows replacing SQLite with PostgreSQL later)."""

    @abstractmethod
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
        """Logs an authorization decision and its execution status."""
        pass

    @abstractmethod
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
        """Queries stored audit events with filtering."""
        pass

    @abstractmethod
    def verify_integrity(self) -> Dict[str, Any]:
        """Verifies the cryptographic hash chain across stored audit records."""
        pass

class SQLiteAuditStore(AuditStore):
    """Thread-safe and multi-process-safe SQLite audit storage implementation with cryptographic hash chain."""

    def __init__(self, db_path: Optional[str] = None, timeout: float = 30.0):
        self._lock = threading.Lock()
        self.timeout = timeout
        if db_path:
            self.db_path = db_path
        elif "AGENTSHIELD_AUDIT_DB" in os.environ:
            self.db_path = os.environ["AGENTSHIELD_AUDIT_DB"]
        elif os.environ.get("VERCEL"):
            self.db_path = os.path.join(tempfile.gettempdir(), "agentshield_audit.db")
        else:
            self.db_path = "agentshield_audit.db"
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
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        agent TEXT NOT NULL,
                        tool TEXT NOT NULL,
                        arguments TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        allowed INTEGER NOT NULL,
                        reasons TEXT NOT NULL,
                        rules_triggered TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        severity TEXT NOT NULL,
                        risk_factors TEXT NOT NULL,
                        execution_status TEXT NOT NULL,
                        error TEXT,
                        policy_version_hash TEXT,
                        prev_hash TEXT,
                        record_hash TEXT,
                        correlation_id TEXT,
                        trace_id TEXT
                    );
                """)
                # Ensure column exists for existing DB files (safe migration)
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(audit_logs);")
                columns = [col["name"] for col in cursor.fetchall()]
                if "policy_version_hash" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN policy_version_hash TEXT;")
                if "prev_hash" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;")
                if "record_hash" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN record_hash TEXT;")
                if "correlation_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN correlation_id TEXT;")
                if "trace_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN trace_id TEXT;")
                if "tenant_id" not in columns:
                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';")

                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_logs(decision);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_logs(tool);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_record_hash ON audit_logs(record_hash);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_correlation_id ON audit_logs(correlation_id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id, timestamp);")
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

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
        corr_id = correlation_id or getattr(decision, "correlation_id", None)
        trc_id = trace_id or getattr(decision, "trace_id", None)
        eff_tenant = getattr(decision, "tenant_id", None) or tenant_id or "default"

        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                # Fetch latest record hash for hash chaining within the immediate transaction
                cursor.execute("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1;")
                latest = cursor.fetchone()
                prev_hash = latest["record_hash"] if latest and latest["record_hash"] else GENESIS_HASH

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

                cursor.execute("""
                    INSERT INTO audit_logs (
                        timestamp, agent, tool, arguments, decision, allowed,
                        reasons, rules_triggered, risk_score, severity,
                        risk_factors, execution_status, error, policy_version_hash,
                        prev_hash, record_hash, correlation_id, trace_id, tenant_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    corr_id,
                    trc_id,
                    eff_tenant,
                ))
                row_id = cursor.lastrowid or 0
                conn.commit()
                return row_id
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                self._close_connection(conn)

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
            conditions.append("decision = ?")
            params.append(decision.upper())
        if agent:
            conditions.append("agent = ?")
            params.append(agent)
        if tool:
            conditions.append("tool = ?")
            params.append(tool)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        if correlation_id:
            conditions.append("correlation_id = ?")
            params.append(correlation_id)
        if tenant_id is not None:
            conditions.append("tenant_id = ?")
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
            LIMIT ?
        """
        params.append(limit)

        records: List[AuditRecord] = []
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(query_sql, params)
            for row in cursor.fetchall():
                row_keys = row.keys()
                records.append(
                    AuditRecord(
                        id=row["id"],
                        timestamp=row["timestamp"],
                        agent=row["agent"],
                        tool=row["tool"],
                        arguments=json.loads(row["arguments"]),
                        decision=row["decision"],
                        allowed=bool(row["allowed"]),
                        reasons=json.loads(row["reasons"]),
                        rules_triggered=json.loads(row["rules_triggered"]),
                        risk_score=row["risk_score"],
                        severity=row["severity"],
                        risk_factors=json.loads(row["risk_factors"]),
                        execution_status=row["execution_status"],
                        error=row["error"],
                        policy_version_hash=row["policy_version_hash"] if "policy_version_hash" in row_keys else None,
                        prev_hash=row["prev_hash"] if "prev_hash" in row_keys else None,
                        record_hash=row["record_hash"] if "record_hash" in row_keys else None,
                        correlation_id=row["correlation_id"] if "correlation_id" in row_keys else None,
                        trace_id=row["trace_id"] if "trace_id" in row_keys else None,
                        tenant_id=row["tenant_id"] if "tenant_id" in row_keys else "default",
                    )
                )
            return records
        finally:
            self._close_connection(conn)

    def verify_integrity(self) -> Dict[str, Any]:
        """Verifies the cryptographic hash chain across all stored audit records.

        Checks that:
        1. The initial record links to GENESIS_HASH.
        2. Every subsequent record's prev_hash strictly equals the predecessor's record_hash.
        3. Every record's record_hash matches the SHA-256 digest of its canonical content.

        Security Notice:
        Hash chaining detects unauthorized record modification, deletion, reordering,
        or insertion in the SQLite database. However, it does not prevent an attacker
        who has full filesystem/write access to the database file from overwriting the entire
        file and recomputing a fresh hash chain. It is tamper-evident, not hardware-immutable.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, agent, tool, arguments, decision, allowed,
                           reasons, rules_triggered, risk_score, severity, risk_factors,
                           execution_status, error, policy_version_hash, prev_hash, record_hash
                    FROM audit_logs
                    ORDER BY id ASC;
                """)
                rows = cursor.fetchall()
                if not rows:
                    return {
                        "valid": True,
                        "total_records": 0,
                        "error": None,
                        "corrupted_record_id": None
                    }

                expected_prev_hash = GENESIS_HASH
                for row in rows:
                    rec_id = row["id"]
                    actual_prev = row["prev_hash"] or GENESIS_HASH
                    if actual_prev != expected_prev_hash:
                        return {
                            "valid": False,
                            "total_records": len(rows),
                            "error": f"Chain link broken at record {rec_id}: prev_hash does not match previous record_hash",
                            "corrupted_record_id": rec_id
                        }

                    recomputed = compute_record_hash(
                        prev_hash=actual_prev,
                        timestamp=row["timestamp"],
                        agent=row["agent"],
                        tool=row["tool"],
                        arguments_json=row["arguments"],
                        decision=row["decision"],
                        allowed=row["allowed"],
                        reasons_json=row["reasons"],
                        rules_triggered_json=row["rules_triggered"],
                        risk_score=row["risk_score"],
                        severity=row["severity"],
                        risk_factors_json=row["risk_factors"],
                        execution_status=row["execution_status"],
                        error=row["error"],
                        policy_version_hash=row["policy_version_hash"],
                    )

                    if row["record_hash"] != recomputed:
                        return {
                            "valid": False,
                            "total_records": len(rows),
                            "error": f"Content tampering detected at record {rec_id}: payload digest mismatch",
                            "corrupted_record_id": rec_id
                        }

                    expected_prev_hash = row["record_hash"]

                return {
                    "valid": True,
                    "total_records": len(rows),
                    "error": None,
                    "corrupted_record_id": None
                }
            except Exception as e:
                return {
                    "valid": False,
                    "total_records": 0,
                    "error": f"Audit verification failed: {str(e)}",
                    "corrupted_record_id": None,
                }
            finally:
                self._close_connection(conn)
