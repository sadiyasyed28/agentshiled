import os
import tempfile
import time
import pytest
from httpx import AsyncClient, ASGITransport

from agentshield.api.app import create_app
from agentshield.shield import Shield
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.events.models import SecurityEvent, SecurityAlert, SecurityIncident, EventSeverity, AlertStatus, IncidentStatus


@pytest.fixture
def multi_tenant_app(monkeypatch):
    """Fixture providing an isolated multi-tenant FastAPI application with separate tenant keys."""
    monkeypatch.setenv("AGENTSHIELD_ADMIN_KEY", "global-platform-admin-key")
    monkeypatch.setenv("AGENTSHIELD_TENANT_KEYS", "tenant_a:key-alpha,tenant_b:key-beta")
    
    with tempfile.NamedTemporaryFile(suffix="_audit.db", delete=False) as f_audit:
        audit_db = f_audit.name
    with tempfile.NamedTemporaryFile(suffix="_reviews.db", delete=False) as f_rev:
        rev_db = f_rev.name
    with tempfile.NamedTemporaryFile(suffix="_events.db", delete=False) as f_ev:
        ev_db = f_ev.name

    app = create_app(
        audit_db_path=audit_db,
        review_db_path=rev_db,
        events_db_path=ev_db,
        admin_api_key="global-platform-admin-key",
        tenant_api_keys={"tenant_a": "key-alpha", "tenant_b": "key-beta"},
    )
    yield app

    for path in (audit_db, rev_db, ev_db):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


@pytest.mark.anyio
async def test_tenant_api_key_authentication(multi_tenant_app):
    """Verifies authentication via X-Tenant-Key header resolves correct tenant and role."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Invalid tenant key -> 401
        res_bad = await client.get("/api/overview", headers={"X-Tenant-Key": "invalid-key"})
        assert res_bad.status_code == 401

        # 2. Valid tenant_a key -> 200, tenant_id='tenant_a'
        res_a = await client.get("/api/overview", headers={"X-Tenant-Key": "key-alpha"})
        assert res_a.status_code == 200
        data_a = res_a.json()
        assert data_a["tenant_id"] == "tenant_a"
        assert data_a["simulated"] is False

        # 3. Valid tenant_b key -> 200, tenant_id='tenant_b'
        res_b = await client.get("/api/overview", headers={"X-Tenant-Key": "key-beta"})
        assert res_b.status_code == 200
        data_b = res_b.json()
        assert data_b["tenant_id"] == "tenant_b"


@pytest.mark.anyio
async def test_tenant_login_session_isolation(multi_tenant_app):
    """Verifies session cookie login binds strictly to tenant_id."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client_a:
        # Login with tenant_a key
        login_res = await client_a.post("/api/auth/login", json={"admin_key": "key-alpha"})
        assert login_res.status_code == 200
        assert login_res.json()["tenant_id"] == "tenant_a"
        assert login_res.json()["role"] == "tenant_admin"

        # Check session
        sess_res = await client_a.get("/api/auth/session")
        assert sess_res.status_code == 200
        assert sess_res.json()["authenticated"] is True
        assert sess_res.json()["tenant_id"] == "tenant_a"
        assert sess_res.json()["role"] == "tenant_admin"


@pytest.mark.anyio
async def test_client_side_tenant_spoofing_prevented(multi_tenant_app):
    """Verifies that an authenticated tenant cannot spoof another tenant via query param or payload."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = {"X-Tenant-Key": "key-alpha"}

        # 1. Attempt to query Tenant B's overview via query parameter
        res_query = await client.get("/api/overview?tenant_id=tenant_b", headers=headers)
        assert res_query.status_code == 403
        assert "cross-tenant access denied" in res_query.json()["detail"].lower()

        # 2. Attempt to query Tenant B's events
        res_events = await client.get("/api/security/events?tenant_id=tenant_b", headers=headers)
        assert res_events.status_code == 403

        # 3. Attempt to pause an agent under Tenant B via request body
        res_pause = await client.post(
            "/incident/pause",
            json={"agent": "foreign_agent", "tenant_id": "tenant_b"},
            headers=headers,
        )
        assert res_pause.status_code == 403

        # 4. Attempt to review Tenant B's items
        res_review = await client.post(
            "/incident/review",
            json={"review_id": "rev-123", "action": "approve", "tenant_id": "tenant_b"},
            headers=headers,
        )
        assert res_review.status_code == 403


@pytest.mark.anyio
async def test_multi_tenant_review_isolation_and_idor(multi_tenant_app):
    """Verifies Tenant A cannot see, approve, or reject Tenant B's pending reviews (IDOR protection)."""
    review_store = multi_tenant_app.state.review_store
    now = time.time()

    dec_a = Decision(
        allowed=False,
        decision=DecisionValue.REVIEW,
        reasons=["human review required"],
        risk_score=0.5,
        severity=RiskLevel.MEDIUM,
        agent="agent_a",
        tool="transfer_funds",
    )
    dec_b = Decision(
        allowed=False,
        decision=DecisionValue.REVIEW,
        reasons=["human review required"],
        risk_score=0.5,
        severity=RiskLevel.MEDIUM,
        agent="agent_b",
        tool="delete_database",
    )

    # Seed review for Tenant A
    review_store.enqueue_review(
        review_id="rev-a-1",
        agent="agent_a",
        tool="transfer_funds",
        arguments={"amount": 500},
        permissions=["transfer"],
        decision=dec_a,
        created_at=now,
        expires_at=now + 3600,
        tenant_id="tenant_a",
    )
    # Seed review for Tenant B
    review_store.enqueue_review(
        review_id="rev-b-1",
        agent="agent_b",
        tool="delete_database",
        arguments={"db": "prod"},
        permissions=["admin"],
        decision=dec_b,
        created_at=now,
        expires_at=now + 3600,
        tenant_id="tenant_b",
    )

    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers_a = {"X-Tenant-Key": "key-alpha"}
        headers_b = {"X-Tenant-Key": "key-beta"}

        # 1. Tenant A lists reviews: should only see rev-a-1
        res_list_a = await client.get("/api/reviews", headers=headers_a)
        assert res_list_a.status_code == 200
        items_a = res_list_a.json()["reviews"]
        ids_a = [r["review_id"] for r in items_a]
        assert "rev-a-1" in ids_a
        assert "rev-b-1" not in ids_a

        # 2. Tenant B lists reviews: should only see rev-b-1
        res_list_b = await client.get("/api/reviews", headers=headers_b)
        assert res_list_b.status_code == 200
        items_b = res_list_b.json()["reviews"]
        ids_b = [r["review_id"] for r in items_b]
        assert "rev-b-1" in ids_b
        assert "rev-a-1" not in ids_b

        # 3. Tenant A attempts to approve Tenant B's review -> 404 (IDOR prevented, review not found in tenant's domain)
        res_idor = await client.post(
            "/incident/review",
            json={"review_id": "rev-b-1", "action": "approve"},
            headers=headers_a,
        )
        assert res_idor.status_code == 404

        # 4. Tenant B's review remains pending
        check_b = review_store.get_review("rev-b-1", tenant_id="tenant_b")
        assert check_b is not None
        assert check_b["status"] == "pending"

        # 5. Tenant A approves own review -> 200
        res_own = await client.post(
            "/incident/review",
            json={"review_id": "rev-a-1", "action": "approve"},
            headers=headers_a,
        )
        assert res_own.status_code == 200
        assert res_own.json()["status"] == "approved"


@pytest.mark.anyio
async def test_multi_tenant_security_events_and_alerts_isolation(multi_tenant_app):
    """Verifies security events and alerts are strictly segregated between tenants."""
    event_store = multi_tenant_app.state.event_store

    # Store event for Tenant A
    ev_a = SecurityEvent(
        event_id="ev-alpha-1",
        timestamp="2026-01-01T00:00:00Z",
        agent_id="agent_a",
        tool="sql_query",
        event_type="access_anomaly",
        severity="medium",
        decision="ALLOW",
        risk_score=0.4,
        evidence="SELECT from customers",
        trace_id="tr-a",
        correlation_id="corr-a",
        metadata={},
        tenant_id="tenant_a",
    )
    event_store.record_event(ev_a)

    # Store event for Tenant B
    ev_b = SecurityEvent(
        event_id="ev-beta-1",
        timestamp="2026-01-01T00:00:00Z",
        agent_id="agent_b",
        tool="bash",
        event_type="command_injection",
        severity="critical",
        decision="BLOCK",
        risk_score=0.95,
        evidence="whoami",
        trace_id="tr-b",
        correlation_id="corr-b",
        metadata={},
        tenant_id="tenant_b",
    )
    event_store.record_event(ev_b)

    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Tenant A queries events
        res_a = await client.get("/api/security/events", headers={"X-Tenant-Key": "key-alpha"})
        assert res_a.status_code == 200
        events_a = res_a.json()["events"]
        ev_ids_a = [e["event_id"] for e in events_a]
        assert "ev-alpha-1" in ev_ids_a
        assert "ev-beta-1" not in ev_ids_a

        # Tenant B queries events
        res_b = await client.get("/api/security/events", headers={"X-Tenant-Key": "key-beta"})
        assert res_b.status_code == 200
        events_b = res_b.json()["events"]
        ev_ids_b = [e["event_id"] for e in events_b]
        assert "ev-beta-1" in ev_ids_b
        assert "ev-alpha-1" not in ev_ids_b


@pytest.mark.anyio
async def test_tenant_scoped_containment_pause_isolation(multi_tenant_app):
    """Verifies that pausing an agent under Tenant A does not pause that agent for Tenant B."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers_a = {"X-Tenant-Key": "key-alpha"}
        headers_b = {"X-Tenant-Key": "key-beta"}

        # Tenant A pauses agent_finance
        res_pause = await client.post("/incident/pause", json={"agent": "agent_finance"}, headers=headers_a)
        assert res_pause.status_code == 200
        assert res_pause.json()["status"] == "paused"

        # Tenant A checks paused agents -> includes agent_finance
        res_list_a = await client.get("/incident/agents", headers=headers_a)
        assert res_list_a.status_code == 200
        assert "agent_finance" in res_list_a.json()["paused_agents"]

        # Tenant B checks paused agents -> does NOT include agent_finance
        res_list_b = await client.get("/incident/agents", headers=headers_b)
        assert res_list_b.status_code == 200
        assert "agent_finance" not in res_list_b.json()["paused_agents"]

        # Tenant A unpauses agent_finance
        res_unpause = await client.post("/incident/unpause", json={"agent": "agent_finance"}, headers=headers_a)
        assert res_unpause.status_code == 200
        assert res_unpause.json()["status"] == "active"


@pytest.mark.anyio
async def test_rbac_tenant_admin_blocked_from_platform_endpoints(multi_tenant_app):
    """Verifies tenant_admin role is strictly forbidden from global platform management endpoints."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        tenant_headers = {"X-Tenant-Key": "key-alpha"}
        global_headers = {"X-Admin-Key": "global-platform-admin-key"}

        # 1. Tenant admin accessing /config -> 403 Forbidden
        res_cfg_tenant = await client.get("/config", headers=tenant_headers)
        assert res_cfg_tenant.status_code == 403
        assert "global platform admin" in res_cfg_tenant.json()["detail"].lower()

        # 2. Tenant admin accessing /audit/verify -> 403 Forbidden
        res_ver_tenant = await client.get("/audit/verify", headers=tenant_headers)
        assert res_ver_tenant.status_code == 403

        # 3. Global admin accessing /config -> 200 OK
        res_cfg_global = await client.get("/config", headers=global_headers)
        assert res_cfg_global.status_code == 200

        # 4. Global admin accessing /audit/verify -> 200 OK
        res_ver_global = await client.get("/audit/verify", headers=global_headers)
        assert res_ver_global.status_code == 200


@pytest.mark.anyio
async def test_honest_empty_states_for_new_tenant(multi_tenant_app):
    """Verifies that a fresh tenant observes strictly genuine zero-metrics, not simulated or fallback data."""
    transport = ASGITransport(app=multi_tenant_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/overview", headers={"X-Tenant-Key": "key-alpha"})
        assert res.status_code == 200
        data = res.json()
        assert data["tenant_id"] == "tenant_a"
        assert data["simulated"] is False
        assert data["total"] == 0
        assert data["pending_reviews_count"] == 0
        assert data["active_incidents_count"] == 0
        assert data["paused_agents"] == []


def test_standalone_sdk_tenancy_defaults():
    """Verifies that the standalone Python SDK operates completely independently with safe defaults."""
    shield = Shield()
    assert shield.is_agent_paused("agent_x") is False

    # Pause under specific tenant
    shield.pause_agent("agent_x", tenant_id="tenant_1")
    assert shield.is_agent_paused("agent_x", tenant_id="tenant_1") is True
    assert shield.is_agent_paused("agent_x", tenant_id="tenant_2") is False
    assert shield.is_agent_paused("agent_x") is False  # default tenant not paused

    # Global containment pause
    shield.pause_agent("agent_y")
    assert shield.is_agent_paused("agent_y", tenant_id="tenant_1") is True
    assert shield.is_agent_paused("agent_y", tenant_id="tenant_2") is True
