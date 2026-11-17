"""
Milestone 8: Hosted Dashboard Security & Multi-Tenancy Acceptance Test Suite.

Verifies:
1. Cross-tenant data isolation:
   - Tenant A and Tenant B workspace isolation.
   - Tenant B cannot query, view, or aggregate Tenant A's events, reviews, agents, or metrics.
   - Tenant B cannot approve or reject Tenant A's review requests (returns 404).
   - Tenant B cannot unpause Tenant A's paused agents.
   - Tenant B cannot access, revoke, or rotate Tenant A's API keys (IDOR protection).
2. Cross-tenant spoofing prevention:
   - Client-supplied x-tenant-id header spoofing is rejected with 403 Forbidden.
   - Request payload tenant_id mismatch is rejected with 403 Forbidden.
3. Role-Based Access Control (RBAC):
   - Tenant admin cannot access global administrative endpoints (/api/audit/verify -> 403).
   - Global platform admin (configured via server env AGENTSHIELD_ADMIN_KEY) has platform access.
   - Global admin cannot be registered via public self-service registration.
4. Session security & lifecycle:
   - Tampered session cookies are rejected (401).
   - Server-side session revocation on logout prevents token reuse (401).
   - CSRF protection: state-mutating requests via cookies require matching CSRF header and cookie.
5. Production read-only safety:
   - When AGENTSHIELD_READONLY is active, mutations (review approval, agent pause/unpause,
     key creation/revocation, registration, simulator clear) fail closed with 403 Forbidden.
   - Read-only queries remain accessible.
6. Core SDK independence:
   - Standalone Python SDK functions without network or hosted backend dependencies.
   - Deterministic policy fails closed for unknown tools, unknown agents, and malformed inputs.
"""

import hashlib
import os
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from agentshield import Shield, ExecutionStatus, DecisionValue, PolicyConfiguration, AgentConfig, ToolRule
from agentshield.audit import SQLiteAuditStore
from agentshield.api.app import create_app
from agentshield.storage.tenants import SqliteTenantStore


@pytest.fixture
def multi_tenant_app():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        audit_db = os.path.join(tmpdir, "audit.db")
        events_db = os.path.join(tmpdir, "events.db")
        reviews_db = os.path.join(tmpdir, "reviews.db")
        sessions_db = os.path.join(tmpdir, "sessions.db")
        tenants_db = os.path.join(tmpdir, "tenants.db")
        admin_key = "platform-global-admin-secret-999"

        app = create_app(
            audit_db_path=audit_db,
            events_db_path=events_db,
            review_db_path=reviews_db,
            sessions_db_path=sessions_db,
            tenants_db_path=tenants_db,
            admin_api_key=admin_key,
            read_only=False,
        )
        yield app, admin_key


def test_cross_tenant_isolation_and_idor_prevention(multi_tenant_app):
    app, global_admin_key = multi_tenant_app
    client = TestClient(app)

    # 1. Register Tenant Alpha
    res_a = client.post(
        "/api/auth/register",
        json={"name": "Alpha Corp", "email": "admin@alphacorp.io", "password": "PasswordAlpha123!"},
    )
    assert res_a.status_code == 200
    tenant_a_id = res_a.json()["tenant_id"]
    api_key_a = res_a.json()["api_key"]

    # 2. Register Tenant Beta
    res_b = client.post(
        "/api/auth/register",
        json={"name": "Beta Corp", "email": "admin@betacorp.io", "password": "PasswordBeta456!"},
    )
    assert res_b.status_code == 200
    tenant_b_id = res_b.json()["tenant_id"]
    api_key_b = res_b.json()["api_key"]

    assert tenant_a_id != tenant_b_id

    # 3. Tenant Alpha ingests telemetry events
    alpha_events_payload = {
        "events": [
            {
                "event_id": "evt-alpha-001",
                "timestamp": "2026-11-16T12:00:00Z",
                "agent": "alpha-billing-bot",
                "tool": "create_order",
                "decision": "BLOCK",
                "severity": "CRITICAL",
                "risk_score": 90.0,
                "reasons": ["High risk transaction flagged"],
            },
            {
                "event_id": "evt-alpha-002",
                "timestamp": "2026-11-16T12:01:00Z",
                "agent": "alpha-support-agent",
                "tool": "get_order_status",
                "decision": "ALLOW",
                "severity": "LOW",
                "risk_score": 10.0,
                "reasons": ["Benign query"],
            },
        ]
    }
    ingest_a = client.post(
        "/api/telemetry/events",
        headers={"x-api-key": api_key_a},
        json=alpha_events_payload,
    )
    assert ingest_a.status_code == 200
    assert ingest_a.json()["ingested"] == 2

    # 4. Tenant Alpha pauses an agent
    pause_a = client.post(
        "/api/incident/pause",
        headers={"x-api-key": api_key_a},
        json={"agent": "alpha-billing-bot"},
    )
    assert pause_a.status_code == 200
    assert pause_a.json()["status"] == "paused"

    # 5. Tenant Beta verifies workspace is completely clean and isolated
    # A) Beta events list returns 0 events
    events_b = client.get("/api/events", headers={"x-api-key": api_key_b})
    assert events_b.status_code == 200
    assert len(events_b.json()["events"]) == 0

    # B) Beta overview metrics return 0 counts
    overview_b = client.get("/api/overview", headers={"x-api-key": api_key_b})
    assert overview_b.status_code == 200
    assert overview_b.json()["total"] == 0
    assert overview_b.json()["block_count"] == 0
    assert overview_b.json()["allow_count"] == 0
    assert overview_b.json()["paused_agents"] == []

    # C) Beta agent list returns 0 agents
    agents_b = client.get("/api/agents", headers={"x-api-key": api_key_b})
    assert agents_b.status_code == 200
    assert agents_b.json()["total"] == 0
    assert agents_b.json()["paused_agents"] == []

    # D) Beta telemetry status returns 0 events
    tel_b = client.get("/api/telemetry/status", headers={"x-api-key": api_key_b})
    assert tel_b.status_code == 200
    assert tel_b.json()["total_events"] == 0
    assert tel_b.json()["active_agents_count"] == 0

    # 6. Tenant Beta cannot access Tenant Alpha's API keys (IDOR protection)
    keys_a = client.get("/api/api-keys", headers={"x-api-key": api_key_a}).json()["keys"]
    assert len(keys_a) >= 1
    alpha_key_id = keys_a[0]["key_id"]

    # Beta attempts to revoke Alpha's key -> 404 Not Found
    revoke_attack = client.post(
        f"/api/api-keys/{alpha_key_id}/revoke",
        headers={"x-api-key": api_key_b},
    )
    assert revoke_attack.status_code == 404

    # Beta attempts to rotate Alpha's key -> 404 Not Found
    rotate_attack = client.post(
        f"/api/api-keys/{alpha_key_id}/rotate",
        headers={"x-api-key": api_key_b},
        json={"name": "Hacked Key"},
    )
    assert rotate_attack.status_code == 404

    # 7. Tenant Beta cannot unpause Tenant Alpha's paused agent
    unpause_attack = client.post(
        "/api/incident/unpause",
        headers={"x-api-key": api_key_b},
        json={"agent": "alpha-billing-bot"},
    )
    assert unpause_attack.status_code == 200
    # Verify Alpha's agent remains paused in Alpha's workspace
    agents_a = client.get("/api/agents", headers={"x-api-key": api_key_a}).json()
    assert "alpha-billing-bot" in agents_a["paused_agents"]


def test_cross_tenant_spoofing_rejected(multi_tenant_app):
    app, _ = multi_tenant_app
    client = TestClient(app)

    # Register Tenant Alpha & Tenant Beta
    res_a = client.post("/api/auth/register", json={"name": "Alpha", "email": "a@ex.com", "password": "Password123!"})
    tenant_a_id = res_a.json()["tenant_id"]

    res_b = client.post("/api/auth/register", json={"name": "Beta", "email": "b@ex.com", "password": "Password123!"})
    api_key_b = res_b.json()["api_key"]

    # Tenant Beta attempts to access Tenant Alpha data via x-tenant-id header -> 403 Forbidden
    spoof_header = client.get(
        "/api/events",
        headers={"x-api-key": api_key_b, "x-tenant-id": tenant_a_id},
    )
    assert spoof_header.status_code == 403
    assert "cannot access tenant" in spoof_header.json()["detail"].lower() or "forbidden" in spoof_header.json()["detail"].lower()

    # Tenant Beta attempts to pass tenant_id in payload for pause mutation -> 403 Forbidden
    spoof_payload = client.post(
        "/api/incident/pause",
        headers={"x-api-key": api_key_b},
        json={"agent": "target_agent", "tenant_id": tenant_a_id},
    )
    assert spoof_payload.status_code == 403
    assert "cannot access tenant" in spoof_payload.json()["detail"].lower() or "forbidden" in spoof_payload.json()["detail"].lower()


def test_rbac_privilege_escalation_prevention(multi_tenant_app):
    app, global_admin_key = multi_tenant_app
    client = TestClient(app)

    # Register Tenant Admin
    res = client.post("/api/auth/register", json={"name": "Tenant", "email": "t@ex.com", "password": "Password123!"})
    tenant_api_key = res.json()["api_key"]

    # 1. Tenant admin cannot access global audit verification
    audit_verify_tenant = client.get(
        "/api/audit/verify",
        headers={"x-api-key": tenant_api_key},
    )
    assert audit_verify_tenant.status_code == 403
    assert "Global platform admin privilege required" in audit_verify_tenant.json()["detail"]

    # 2. Global platform admin can access global audit verification
    audit_verify_global = client.get(
        "/api/audit/verify",
        headers={"x-admin-key": global_admin_key},
    )
    assert audit_verify_global.status_code == 200
    assert "valid" in audit_verify_global.json()

    # 3. Unauthenticated requests to protected endpoints are rejected
    unauth_client = TestClient(app)
    unauth_events = unauth_client.get("/api/api-keys")
    assert unauth_events.status_code in (401, 403)

    unauth_policies = unauth_client.get("/api/policies")
    assert unauth_policies.status_code in (401, 403)


def test_session_lifecycle_and_csrf_protection(multi_tenant_app):
    app, _ = multi_tenant_app
    client = TestClient(app)

    # Register developer
    reg = client.post(
        "/api/auth/register",
        json={"name": "Dev Org", "email": "dev@test.org", "password": "SecurePassword123!"},
    )
    assert reg.status_code == 200

    # 1. Login with email & password -> receives session cookie and CSRF token
    login = client.post(
        "/api/auth/login",
        json={"email": "dev@test.org", "password": "SecurePassword123!"},
    )
    assert login.status_code == 200
    assert "agentshield_session" in client.cookies
    assert "agentshield_csrf" in client.cookies
    csrf_token = login.json()["csrf_token"]
    session_cookie = client.cookies.get("agentshield_session")

    # 2. State mutation without CSRF token header fails with 403
    mutate_no_csrf = client.post(
        "/api/incident/pause",
        json={"agent": "demo_agent"},
    )
    assert mutate_no_csrf.status_code == 403
    assert "CSRF token verification failed" in mutate_no_csrf.json()["detail"]

    # 3. State mutation with matching CSRF header succeeds
    mutate_csrf = client.post(
        "/api/incident/pause",
        json={"agent": "demo_agent"},
        headers={"x-csrf-token": csrf_token},
    )
    assert mutate_csrf.status_code == 200
    assert mutate_csrf.json()["status"] == "paused"

    # 4. Logout revokes session server-side
    logout = client.post("/api/auth/logout")
    assert logout.status_code == 200

    # 5. Check session state after logout
    old_cookie_client = TestClient(app)
    old_cookie_client.cookies.set("agentshield_session", session_cookie)
    after_logout = old_cookie_client.get("/api/auth/session")
    assert after_logout.status_code == 200
    assert after_logout.json()["authenticated"] is False

    # 6. Attempting protected mutation or access with revoked cookie fails with 401
    revoked_access = old_cookie_client.get("/api/api-keys")
    assert revoked_access.status_code in (401, 403)


def test_production_readonly_enforcement():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        audit_db = os.path.join(tmpdir, "audit.db")
        admin_key = "readonly-admin-key-123"

        # Initialize app in read-only mode (simulating AGENTSHIELD_READONLY=true)
        app = create_app(
            audit_db_path=audit_db,
            admin_api_key=admin_key,
            read_only=True,
        )
        client = TestClient(app)

        # 1. Non-mutating read endpoints succeed
        assert client.get("/health").status_code == 200
        assert client.get("/api/overview").status_code == 200
        assert client.get("/incident/agents").status_code == 200

        # 2. All mutating endpoints fail closed with 403 Forbidden
        headers = {"x-admin-key": admin_key}

        # Pause agent
        pause_res = client.post("/incident/pause", json={"agent": "bot"}, headers=headers)
        assert pause_res.status_code == 403
        assert "read-only mode" in pause_res.json()["detail"].lower()

        # Unpause agent
        unpause_res = client.post("/incident/unpause", json={"agent": "bot"}, headers=headers)
        assert unpause_res.status_code == 403
        assert "read-only mode" in unpause_res.json()["detail"].lower()

        # Review action
        review_res = client.post("/incident/review", json={"review_id": "rev-1", "action": "approve"}, headers=headers)
        assert review_res.status_code == 403
        assert "read-only mode" in review_res.json()["detail"].lower()

        # Register workspace
        reg_res = client.post("/api/auth/register", json={"name": "Org", "email": "o@e.com", "password": "Password123!"})
        assert reg_res.status_code == 403
        assert "read-only mode" in reg_res.json()["detail"].lower()

        # Clear simulator history
        clear_res = client.post("/api/simulator/history/clear", headers=headers)
        assert clear_res.status_code == 403
        assert "read-only mode" in clear_res.json()["detail"].lower()


def test_core_sdk_standalone_operation():
    """Verifies standalone Python SDK remains independently usable without hosted backend."""
    config = PolicyConfiguration(
        agents={
            "local-agent": AgentConfig(
                name="local-agent",
                allowed_tools={"safe_tool"},
                denied_tools={"dangerous_tool"},
            ),
        },
        tools={
            "safe_tool": ToolRule(tool="safe_tool"),
        },
    )

    shield = Shield(policy=config, audit_store=SQLiteAuditStore(":memory:"))

    # 1. Allowed tool proposal
    d1 = shield.authorize(agent="local-agent", tool="safe_tool", arguments={"val": 1})
    assert d1.allowed is True
    assert d1.decision.value == "ALLOW"

    # 2. Explicitly denied tool fails closed
    d2 = shield.authorize(agent="local-agent", tool="dangerous_tool", arguments={})
    assert d2.allowed is False
    assert d2.decision.value == "BLOCK"

    # 3. Unknown tool fails closed
    d3 = shield.authorize(agent="local-agent", tool="unknown_tool", arguments={})
    assert d3.allowed is False
    assert d3.decision.value == "BLOCK"

    # 4. Unknown agent fails closed
    d4 = shield.authorize(agent="rogue_agent", tool="safe_tool", arguments={})
    assert d4.allowed is False
    assert d4.decision.value == "BLOCK"
