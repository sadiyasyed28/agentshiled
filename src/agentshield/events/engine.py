"""
Security Event Manager and Alert/Incident Coordinator for AgentShield.

Manages event ingestion, deterministic alert rule evaluation, correlation grouping,
and incident lifecycle progression.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from agentshield.events.models import (
    SecurityEvent,
    SecurityAlert,
    SecurityIncident,
    EventType,
    EventSeverity,
    AlertStatus,
    IncidentStatus,
)
from agentshield.events.rules import AlertRuleEngine
from agentshield.events.store import EventStore, SQLiteEventStore
from agentshield.review.store import sanitize_arguments_for_storage
from agentshield.audit.store import redact_sensitive_data


def _compare_severity(sev1: str, sev2: str) -> str:
    order = {EventSeverity.LOW.value: 1, EventSeverity.MEDIUM.value: 2, EventSeverity.HIGH.value: 3, EventSeverity.CRITICAL.value: 4}
    score1 = order.get(sev1.upper(), 1)
    score2 = order.get(sev2.upper(), 1)
    return sev1 if score1 >= score2 else sev2


class SecurityEventManager:
    """Central engine for recording events, generating alerts, and correlating incidents."""

    def __init__(
        self,
        store: Optional[EventStore] = None,
        rule_engine: Optional[AlertRuleEngine] = None,
    ):
        self.store: EventStore = store if store is not None else SQLiteEventStore()
        self.rule_engine: AlertRuleEngine = rule_engine if rule_engine is not None else AlertRuleEngine()

    def publish_event(
        self,
        agent_id: str,
        tool: str,
        event_type: str,
        severity: str = EventSeverity.LOW.value,
        decision: Optional[str] = None,
        risk_score: float = 0.0,
        evidence: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = "default",
    ) -> SecurityEvent:
        """Publishes a security event, evaluates alert rules, and correlates incidents."""
        evt_trace = trace_id or f"trc_{uuid.uuid4().hex[:12]}"
        evt_corr = correlation_id or evt_trace
        effective_tenant = tenant_id or "default"

        clean_evidence = [redact_sensitive_data(e) for e in (evidence or [])]
        clean_metadata = sanitize_arguments_for_storage(metadata or {})
        clean_metadata = redact_sensitive_data(clean_metadata)
        if not isinstance(clean_metadata, dict):
            clean_metadata = {"data": clean_metadata}

        event = SecurityEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id or "unknown",
            tool=tool or "unknown",
            event_type=event_type,
            severity=severity,
            decision=decision,
            risk_score=float(risk_score),
            evidence=clean_evidence,
            trace_id=evt_trace,
            correlation_id=evt_corr,
            metadata=clean_metadata,
            tenant_id=effective_tenant,
        )

        # 1. Record event
        self.store.record_event(event)

        # 2. Fetch recent events for context and evaluate deterministic alert rules
        recent_events = self.store.get_recent_events_for_agent(event.agent_id, limit=20)
        alerts = self.rule_engine.evaluate(event, recent_events)

        # 3. For each triggered alert, link to or create correlated incident
        for alert in alerts:
            alert.tenant_id = effective_tenant
            if hasattr(self.store, "record_alert_and_correlate"):
                self.store.record_alert_and_correlate(alert, event)
            else:
                self._correlate_and_store_alert(alert, event)

        return event

    def _correlate_and_store_alert(self, alert: SecurityAlert, trigger_event: SecurityEvent) -> None:
        """Correlates an alert to an existing incident by correlation_id, or opens a new incident."""
        effective_tenant = alert.tenant_id or trigger_event.tenant_id or "default"
        alert.tenant_id = effective_tenant
        trigger_event.tenant_id = effective_tenant
        existing_incident = self.store.get_incident_by_correlation(alert.correlation_id, tenant_id=effective_tenant)

        if existing_incident:
            # Correlate alert with existing incident
            alert.incident_id = existing_incident.incident_id
            new_sev = _compare_severity(existing_incident.severity, alert.severity)
            self.store.update_incident(
                incident_id=existing_incident.incident_id,
                severity=new_sev,
                add_alert_id=alert.alert_id,
                increment_event_count=1,
                tenant_id=effective_tenant,
            )
        elif alert.severity in (EventSeverity.HIGH.value, EventSeverity.CRITICAL.value):
            # Auto-open incident for high or critical alert
            new_inc = SecurityIncident(
                incident_id=f"inc_{uuid.uuid4().hex[:12]}",
                title=f"Incident: {alert.title}",
                description=alert.description,
                severity=alert.severity,
                status=IncidentStatus.OPEN.value,
                correlation_id=alert.correlation_id,
                agent_id=alert.agent_id,
                alert_ids=[alert.alert_id],
                event_count=1,
                metadata={
                    "first_alert_type": alert.alert_type,
                    "first_tool": trigger_event.tool,
                },
                tenant_id=effective_tenant,
            )
            self.store.create_incident(new_inc)
            alert.incident_id = new_inc.incident_id

        self.store.create_alert(alert)

    # Event queries
    def get_event(self, event_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityEvent]:
        return self.store.get_event(event_id, tenant_id=tenant_id)

    def query_events(self, **kwargs) -> List[SecurityEvent]:
        return self.store.query_events(**kwargs)

    # Alert queries & management
    def get_alert(self, alert_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        return self.store.get_alert(alert_id, tenant_id=tenant_id)

    def query_alerts(self, **kwargs) -> List[SecurityAlert]:
        return self.store.query_alerts(**kwargs)

    def acknowledge_alert(self, alert_id: str, actor: str, note: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        return self.store.update_alert_status(alert_id, status=AlertStatus.ACKNOWLEDGED.value, actor=actor, note=note, tenant_id=tenant_id)

    def investigate_alert(self, alert_id: str, actor: str, note: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        return self.store.update_alert_status(alert_id, status=AlertStatus.INVESTIGATING.value, actor=actor, note=note, tenant_id=tenant_id)

    def resolve_alert(self, alert_id: str, actor: str, note: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        return self.store.update_alert_status(alert_id, status=AlertStatus.RESOLVED.value, actor=actor, note=note, tenant_id=tenant_id)

    def dismiss_alert(self, alert_id: str, actor: str, note: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[SecurityAlert]:
        return self.store.update_alert_status(alert_id, status=AlertStatus.DISMISSED.value, actor=actor, note=note, tenant_id=tenant_id)

    # Incident queries & management
    def get_incident(self, incident_id: str, tenant_id: Optional[str] = None) -> Optional[SecurityIncident]:
        return self.store.get_incident(incident_id, tenant_id=tenant_id)

    def query_incidents(self, **kwargs) -> List[SecurityIncident]:
        return self.store.query_incidents(**kwargs)

    def update_incident(self, incident_id: str, **kwargs) -> Optional[SecurityIncident]:
        return self.store.update_incident(incident_id, **kwargs)

