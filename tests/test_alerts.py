"""
Tests for AgentShield Security Alert endpoints and incident lifecycle.
Verifies authentication enforcement, querying, filtering, and tenant isolation.
"""

import pytest
from fastapi.testclient import TestClient

from agentshield.api.app import create_app
from agentshield.events.models import SecurityAlert, EventSeverity, AlertStatus


@pytest.fixture
def test_app():
    app = create_app(
        audit_db_path=":memory:",
        admin_api_key="alerts_admin_secret",
        events_db_path=":memory:",
        tenant_api_keys={"tenant_alpha": "alpha_secret", "tenant_beta": "beta_secret"},
    )
    return app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


def test_list_alerts_unauthenticated(client):
    """Unauthenticated requests to /api/incident/alerts must return 401."""
    resp = client.get("/api/incident/alerts")
    assert resp.status_code == 401


def test_list_alerts_authenticated_empty(client):
    """Authenticated request when no alerts exist returns empty list."""
    headers = {"x-admin-key": "alerts_admin_secret"}
    resp = client.get("/api/incident/alerts", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["alerts"] == []
    assert data["total"] == 0


def test_list_alerts_with_seeded_alerts(test_app, client):
    """Authenticated admin can query alerts with filters."""
    event_manager = getattr(test_app.state.shield, "event_manager", None)
    assert event_manager is not None

    alert1 = SecurityAlert(
        alert_id="alt_test_001",
        title="Prompt Injection Alert",
        description="Suspicious prompt injection pattern",
        alert_type="prompt_injection",
        severity=EventSeverity.CRITICAL.value,
        status=AlertStatus.OPEN.value,
        agent_id="agent_alpha",
        tenant_id="default",
    )
    alert2 = SecurityAlert(
        alert_id="alt_test_002",
        title="Volume Quota Exceeded",
        description="Agent exceeded 10 calls/min",
        alert_type="quota_exceeded",
        severity=EventSeverity.MEDIUM.value,
        status=AlertStatus.ACKNOWLEDGED.value,
        agent_id="agent_beta",
        tenant_id="default",
    )
    event_manager.store.create_alert(alert1)
    event_manager.store.create_alert(alert2)

    headers = {"x-admin-key": "alerts_admin_secret"}

    # Query all
    resp = client.get("/api/incident/alerts", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2

    # Filter by severity
    resp_crit = client.get("/api/incident/alerts?severity=CRITICAL", headers=headers)
    assert resp_crit.status_code == 200
    assert resp_crit.json()["total"] == 1
    assert resp_crit.json()["alerts"][0]["alert_id"] == "alt_test_001"

    # Filter by agent
    resp_agent = client.get("/api/incident/alerts?agent_id=agent_beta", headers=headers)
    assert resp_agent.status_code == 200
    assert resp_agent.json()["total"] == 1
    assert resp_agent.json()["alerts"][0]["alert_id"] == "alt_test_002"


def test_get_individual_alert(test_app, client):
    """Retrieve individual alert by ID or return 404."""
    event_manager = test_app.state.shield.event_manager
    alert = SecurityAlert(
        alert_id="alt_single_123",
        title="SSRF Attempt",
        description="Localhost destination blocked",
        severity=EventSeverity.HIGH.value,
        agent_id="test_agent",
        tenant_id="default",
    )
    event_manager.store.create_alert(alert)

    headers = {"x-admin-key": "alerts_admin_secret"}

    resp = client.get("/api/security/alerts/alt_single_123", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["alert_id"] == "alt_single_123"

    resp_404 = client.get("/api/security/alerts/alt_nonexistent", headers=headers)
    assert resp_404.status_code == 404


def test_tenant_isolation_alerts(test_app, client):
    """Tenant admin only sees alerts belonging to their tenant."""
    event_manager = test_app.state.shield.event_manager
    alert_a = SecurityAlert(
        alert_id="alt_tenant_a",
        title="Alpha Alert",
        tenant_id="tenant_alpha",
    )
    alert_b = SecurityAlert(
        alert_id="alt_tenant_b",
        title="Beta Alert",
        tenant_id="tenant_beta",
    )
    event_manager.store.create_alert(alert_a)
    event_manager.store.create_alert(alert_b)

    # Tenant Alpha
    resp_a = client.get("/api/incident/alerts", headers={"x-tenant-key": "alpha_secret"})
    assert resp_a.status_code == 200
    ids_a = [a["alert_id"] for a in resp_a.json()["alerts"]]
    assert "alt_tenant_a" in ids_a
    assert "alt_tenant_b" not in ids_a

    # Tenant Beta
    resp_b = client.get("/api/incident/alerts", headers={"x-tenant-key": "beta_secret"})
    assert resp_b.status_code == 200
    ids_b = [a["alert_id"] for a in resp_b.json()["alerts"]]
    assert "alt_tenant_b" in ids_b
    assert "alt_tenant_a" not in ids_b
