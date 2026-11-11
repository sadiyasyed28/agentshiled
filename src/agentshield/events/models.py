"""
Standardized Security Event, Alert, and Incident models for AgentShield.

Designed for deterministic detection, immutable correlation, and safe consumption
by future read-only LLM Security Analysts without exposing credentials or raw secrets.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class EventType(str, Enum):
    AUTHORIZATION_DECISION = "authorization_decision"
    POLICY_VIOLATION = "policy_violation"
    RISK_DETECTION = "risk_detection"
    EXECUTION_OUTCOME = "execution_outcome"
    REVIEW_ACTION = "review_action"
    SECURITY_FAILURE = "security_failure"
    INPUT_CHECK = "input_check"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    LOOP_DETECTED = "loop_detected"


class EventSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class SecurityEvent:
    """Standardized Security Event representation across all pipeline stages."""
    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: str = "unknown"
    tool: str = "unknown"
    event_type: str = EventType.AUTHORIZATION_DECISION.value
    severity: str = EventSeverity.LOW.value
    decision: Optional[str] = None
    risk_score: float = 0.0
    evidence: List[str] = field(default_factory=list)
    trace_id: str = field(default_factory=lambda: f"trc_{uuid.uuid4().hex[:12]}")
    correlation_id: str = field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}")
    metadata: Dict[str, Any] = field(default_factory=dict)
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_analyst_dict(self) -> Dict[str, Any]:
        """Provides a safe, summarized representation for an LLM Security Analyst.
        Guarantees no raw credentials or sensitive data are included."""
        from agentshield.review.store import sanitize_arguments_for_storage
        from agentshield.audit.store import redact_sensitive_data

        safe_metadata = {}
        for k, v in self.metadata.items():
            if k in ("raw_credential", "api_key", "password", "token", "secret", "credentials"):
                continue
            cleaned = sanitize_arguments_for_storage(v)
            cleaned = redact_sensitive_data(cleaned)
            safe_metadata[k] = cleaned

        safe_evidence = [redact_sensitive_data(e) for e in self.evidence]

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "event_type": self.event_type,
            "severity": self.severity,
            "decision": self.decision,
            "risk_score": float(f"{self.risk_score:.2f}"),
            "evidence": safe_evidence,
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "summary": (
                f"[{self.severity}] {self.event_type} on tool '{self.tool}' by agent '{self.agent_id}' "
                f"(Decision: {self.decision or 'N/A'}, Risk: {self.risk_score:.1f})"
            ),
            "context": safe_metadata,
        }


@dataclass
class SecurityAlert:
    """Security Alert triggered by deterministic security detection rules."""
    alert_id: str = field(default_factory=lambda: f"alt_{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    title: str = "Security Alert"
    description: str = ""
    alert_type: str = "generic_alert"
    severity: str = EventSeverity.MEDIUM.value
    status: str = AlertStatus.OPEN.value
    agent_id: str = "unknown"
    trigger_event_id: str = ""
    event_ids: List[str] = field(default_factory=list)
    correlation_id: str = ""
    incident_id: Optional[str] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_note: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityIncident:
    """Security Incident grouping correlated alerts and events."""
    incident_id: str = field(default_factory=lambda: f"inc_{uuid.uuid4().hex[:12]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    title: str = "Security Incident"
    description: str = ""
    severity: str = EventSeverity.HIGH.value
    status: str = IncidentStatus.OPEN.value
    correlation_id: str = ""
    agent_id: str = "unknown"
    alert_ids: List[str] = field(default_factory=list)
    event_count: int = 0
    assigned_to: Optional[str] = None
    resolution_summary: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tenant_id: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

