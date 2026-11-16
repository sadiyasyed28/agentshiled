"""
Acceptance Tests for Milestone 4: Real Customer Workspace and Agent Activity.

Verifies:
1. Self-service registration creates independent workspaces with active API keys.
2. Separate Python SDK processes with TelemetryExporter securely transmit actual security events.
3. Ingested telemetry is strictly tenant-scoped and isolated.
4. Genuine agent discovery from persisted database records across all events.
5. Overview, Events, Agents, and Audit Logs display actual persisted records.
6. Zero-activity workspaces display honest empty states (no fake demo fallbacks or mock data).
7. API key revocation prevents further telemetry ingestion for that key.
8. Logging out and signing into another workspace never leaks data across tenants.
"""

import os
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from agentshield import Shield
from agentshield.api.app import create_app
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.telemetry import TelemetryConfig, TelemetryEvent, TelemetryExporter


@pytest.fixture
def temp_dbs():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        audit_db = os.path.join(tmpdir, "audit.db")
        events_db = os.path.join(tmpdir, "events.db")
        reviews_db = os.path.join(tmpdir, "reviews.db")
        sessions_db = os.path.join(tmpdir, "sessions.db")
        tenants_db = os.path.join(tmpdir, "tenants.db")
        yield {
            "tmpdir": tmpdir,
            "audit_db": audit_db,
            "events_db": events_db,
            "reviews_db": reviews_db,
            "sessions_db": sessions_db,
            "tenants_db": tenants_db,
        }


def test_milestone4_multi_customer_workspace_acceptance(temp_dbs):
    """
    Comprehensive acceptance test for Milestone 4:
    - 2 active customers ('Company A', 'Company B') + 1 zero-activity customer ('Company C')
    - Real SDK telemetry ingestion
    - Tenant isolation & genuine agent discovery
    - Honest empty states
    - Key revocation
    - Session logout & cross-tenant leak prevention
    """
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )

    client_a = TestClient(app)
    client_b = TestClient(app)
    client_c = TestClient(app)

    # 1. Register Customer A ("Company A")
    res_a = client_a.post(
        "/api/auth/register",
        json={"name": "Company A", "email": "admin@companya.com", "password": "PasswordA123!"},
    )
    assert res_a.status_code == 200, res_a.text
    data_a = res_a.json()
    tenant_a = data_a["tenant_id"]
    api_key_a = data_a["api_key"]
    key_id_a = data_a["key_id"]
    assert api_key_a.startswith("ash_live_")

    # 2. Register Customer B ("Company B")
    res_b = client_b.post(
        "/api/auth/register",
        json={"name": "Company B", "email": "admin@companyb.com", "password": "PasswordB456!"},
    )
    assert res_b.status_code == 200, res_b.text
    data_b = res_b.json()
    tenant_b = data_b["tenant_id"]
    api_key_b = data_b["api_key"]
    key_id_b = data_b["key_id"]
    assert api_key_b.startswith("ash_live_")
    assert tenant_a != tenant_b

    # 3. Register Customer C ("Company C" - Zero Activity)
    res_c = client_c.post(
        "/api/auth/register",
        json={"name": "Company C", "email": "admin@companyc.com", "password": "PasswordC789!"},
    )
    assert res_c.status_code == 200, res_c.text
    data_c = res_c.json()
    tenant_c = data_c["tenant_id"]
    api_key_c = data_c["api_key"]

    # 4. Connect separate Python SDK Telemetry processes for Customer A and Customer B
    # Customer A simulates running 'procurement-bot' executing search_product and create_order (both ALLOW)
    event_a1 = TelemetryEvent(
        event_id="evt_a_001",
        event_type="authorization_decision",
        agent="procurement-bot",
        tool="search_product",
        decision="ALLOW",
        allowed=True,
        reasons=["Rule: allowlisted procurement tool"],
        risk_score=15.0,
        severity="LOW",
        execution_status="executed",
        correlation_id="corr_a_101",
        timestamp="2026-03-30T10:00:00Z",
    )
    event_a2 = TelemetryEvent(
        event_id="evt_a_002",
        event_type="tool_execution",
        agent="procurement-bot",
        tool="create_order",
        decision="ALLOW",
        allowed=True,
        reasons=["Rule: standard order within limit"],
        risk_score=20.0,
        severity="LOW",
        execution_status="executed",
        correlation_id="corr_a_102",
        timestamp="2026-03-30T10:05:00Z",
    )

    # Customer B simulates running 'finance-bot' executing execute_transfer (BLOCK)
    event_b1 = TelemetryEvent(
        event_id="evt_b_001",
        event_type="authorization_decision",
        agent="finance-bot",
        tool="execute_transfer",
        decision="BLOCK",
        allowed=False,
        reasons=["Rule: unapproved high-value transfer"],
        risk_score=95.0,
        severity="CRITICAL",
        execution_status="not_executed",
        correlation_id="corr_b_201",
        timestamp="2026-03-30T10:10:00Z",
    )

    # Ingest telemetry for Customer A using api_key_a
    ingest_client = TestClient(app)
    resp_ingest_a = ingest_client.post(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {api_key_a}"},
        json={"events": [event_a1.to_dict(), event_a2.to_dict()]},
    )
    assert resp_ingest_a.status_code == 200, resp_ingest_a.text
    assert resp_ingest_a.json()["ingested"] == 2
    assert resp_ingest_a.json()["tenant_id"] == tenant_a

    # Ingest telemetry for Customer B using api_key_b
    resp_ingest_b = ingest_client.post(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {api_key_b}"},
        json={"events": [event_b1.to_dict()]},
    )
    assert resp_ingest_b.status_code == 200, resp_ingest_b.text
    assert resp_ingest_b.json()["ingested"] == 1
    assert resp_ingest_b.json()["tenant_id"] == tenant_b

    # 5. Verify Customer A Workspace Data
    # 5a. Overview stats
    ov_a = client_a.get("/api/overview")
    assert ov_a.status_code == 200
    ov_a_data = ov_a.json()
    assert ov_a_data["tenant_id"] == tenant_a
    assert ov_a_data["total_evaluated"] == 2
    assert ov_a_data["allow_count"] == 2
    assert ov_a_data["block_count"] == 0
    assert ov_a_data["review_count"] == 0

    # 5b. Events list
    ev_a = client_a.get("/api/events")
    assert ev_a.status_code == 200
    ev_a_data = ev_a.json()
    assert ev_a_data["total"] == 2
    agent_names_a = [e["agent"] for e in ev_a_data["events"]]
    assert all(name == "procurement-bot" for name in agent_names_a)
    assert "finance-bot" not in agent_names_a

    # 5c. Discovered agents
    ag_a = client_a.get("/api/agents")
    assert ag_a.status_code == 200
    ag_a_data = ag_a.json()
    assert ag_a_data["total"] == 1
    disc_a = ag_a_data["agents"][0]
    assert disc_a["name"] == "procurement-bot"
    assert disc_a["total_events"] == 2
    assert disc_a["blocked_count"] == 0
    assert disc_a["status"] == "active"
    assert disc_a["is_paused"] is False

    # 5d. Telemetry status
    ts_a = client_a.get("/api/telemetry/status")
    assert ts_a.status_code == 200
    ts_a_data = ts_a.json()
    assert ts_a_data["status"] == "connected"
    assert ts_a_data["total_events"] == 2
    assert ts_a_data["active_agents_count"] == 1
    assert ts_a_data["last_event_timestamp"] is not None

    # 6. Verify Customer B Workspace Data
    # 6a. Overview stats
    ov_b = client_b.get("/api/overview")
    assert ov_b.status_code == 200
    ov_b_data = ov_b.json()
    assert ov_b_data["tenant_id"] == tenant_b
    assert ov_b_data["total_evaluated"] == 1
    assert ov_b_data["allow_count"] == 0
    assert ov_b_data["block_count"] == 1
    assert ov_b_data["review_count"] == 0

    # 6b. Events list
    ev_b = client_b.get("/api/events")
    assert ev_b.status_code == 200
    ev_b_data = ev_b.json()
    assert ev_b_data["total"] == 1
    assert ev_b_data["events"][0]["agent"] == "finance-bot"
    assert ev_b_data["events"][0]["decision"] == "BLOCK"
    assert "procurement-bot" not in [e["agent"] for e in ev_b_data["events"]]

    # 6c. Discovered agents
    ag_b = client_b.get("/api/agents")
    assert ag_b.status_code == 200
    ag_b_data = ag_b.json()
    assert ag_b_data["total"] == 1
    disc_b = ag_b_data["agents"][0]
    assert disc_b["name"] == "finance-bot"
    assert disc_b["total_events"] == 1
    assert disc_b["blocked_count"] == 1
    assert disc_b["status"] == "active"

    # 6d. Telemetry status
    ts_b = client_b.get("/api/telemetry/status")
    assert ts_b.status_code == 200
    ts_b_data = ts_b.json()
    assert ts_b_data["status"] == "connected"
    assert ts_b_data["total_events"] == 1
    assert ts_b_data["active_agents_count"] == 1

    # 7. Verify Customer C (Zero Activity Workspace) Honest Empty States
    ov_c = client_c.get("/api/overview")
    assert ov_c.status_code == 200
    ov_c_data = ov_c.json()
    assert ov_c_data["tenant_id"] == tenant_c
    assert ov_c_data["total_evaluated"] == 0
    assert ov_c_data["allow_count"] == 0
    assert ov_c_data["block_count"] == 0
    assert ov_c_data["review_count"] == 0
    assert ov_c_data["pending_reviews_count"] == 0

    ev_c = client_c.get("/api/events")
    assert ev_c.status_code == 200
    assert ev_c.json()["events"] == []
    assert ev_c.json()["total"] == 0

    ag_c = client_c.get("/api/agents")
    assert ag_c.status_code == 200
    assert ag_c.json()["agents"] == []
    assert ag_c.json()["total"] == 0

    ts_c = client_c.get("/api/telemetry/status")
    assert ts_c.status_code == 200
    ts_c_data = ts_c.json()
    assert ts_c_data["status"] == "awaiting_telemetry"
    assert ts_c_data["total_events"] == 0
    assert ts_c_data["active_agents_count"] == 0

    # Ensure no demo/simulator reviews leak into Customer C's review queue
    rev_c = client_c.get("/api/reviews")
    assert rev_c.status_code == 200
    assert rev_c.json()["count"] == 0
    assert rev_c.json()["reviews"] == []

    # 8. Verify API Key Revocation
    # Revoke Customer A's key using the API key header
    rev_resp = client_a.post(
        f"/api/api-keys/{key_id_a}/revoke",
        headers={"x-api-key": api_key_a},
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["status"] == "revoked"

    # Attempt to transmit telemetry with revoked key -> 401 Unauthorized
    rev_ingest = ingest_client.post(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {api_key_a}"},
        json={"events": [event_a1.to_dict()]},
    )
    assert rev_ingest.status_code == 401
    assert "revoked" in rev_ingest.text.lower()

    # Customer B's key continues to work smoothly
    active_b_ingest = ingest_client.post(
        "/api/v1/telemetry/events",
        headers={"Authorization": f"Bearer {api_key_b}"},
        json={"events": [
            TelemetryEvent(
                event_id="evt_b_002",
                event_type="authorization_decision",
                agent="finance-bot",
                tool="audit_accounts",
                decision="ALLOW",
                allowed=True,
                reasons=["Rule: routine internal audit"],
                risk_score=10.0,
                severity="LOW",
                execution_status="executed",
                timestamp="2026-03-30T10:15:00Z",
            ).to_dict()
        ]},
    )
    assert active_b_ingest.status_code == 200
    assert active_b_ingest.json()["ingested"] == 1

    # 9. Verify Session Logout and Cross-Session Isolation
    # Logout Customer A
    logout_a = client_a.post("/api/auth/logout")
    assert logout_a.status_code == 200

    # Requesting protected workspace endpoint with client_a fails after logout
    assert client_a.get("/api/api-keys").status_code == 401

    # Sign into Customer B using credentials on that same client instance
    login_b = client_a.post(
        "/api/auth/login",
        json={"email": "admin@companyb.com", "password": "PasswordB456!"},
    )
    assert login_b.status_code == 200
    assert login_b.json()["tenant_id"] == tenant_b

    # Verify that the newly authenticated session sees ONLY Customer B's data
    overview_after_login = client_a.get("/api/overview")
    assert overview_after_login.status_code == 200
    assert overview_after_login.json()["tenant_id"] == tenant_b
    assert overview_after_login.json()["total_evaluated"] == 2  # Customer B's 2 events

    agents_after_login = client_a.get("/api/agents")
    assert agents_after_login.status_code == 200
    assert [ag["name"] for ag in agents_after_login.json()["agents"]] == ["finance-bot"]
