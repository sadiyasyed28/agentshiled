"""
Integration tests for AgentShield hosted backend telemetry ingestion:
- Authentication & Authorization
- Tenant isolation & cross-tenant rejection
- Storage persistence in audit and event stores
- Reflection in GET /api/overview and GET /api/events
- Deduplication handling
- Read-only protection preservation
"""

import os
from fastapi.testclient import TestClient
import pytest

from agentshield.api.app import create_app
from agentshield.audit import SQLiteAuditStore
from agentshield.events import SQLiteEventStore
from agentshield.review import SQLiteReviewStore


@pytest.fixture
def telemetry_app(tmp_path):
    audit_db = str(tmp_path / "telemetry_audit.db")
    events_db = str(tmp_path / "telemetry_events.db")
    review_db = str(tmp_path / "telemetry_review.db")

    tenant_keys = {
        "tenant-alpha": "key-alpha-12345",
        "tenant-beta": "key-beta-67890",
    }
    app = create_app(
        admin_api_key="global-admin-key",
        tenant_api_keys=tenant_keys,
        audit_db_path=audit_db,
        events_db_path=events_db,
        review_db_path=review_db,
        read_only=False,
    )
    return app


def test_telemetry_ingest_authentication_required(telemetry_app):
    client = TestClient(telemetry_app)

    # 1. No auth headers -> 401
    res = client.post("/api/v1/telemetry/events", json={"events": []})
    assert res.status_code == 401
    assert "Unauthorized" in res.json()["detail"]

    # 2. Invalid auth key -> 401
    res = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "invalid-bogus-key"},
        json={"events": []},
    )
    assert res.status_code == 401


def test_telemetry_ingest_tenant_isolation(telemetry_app):
    client = TestClient(telemetry_app)

    # Tenant Alpha key attempting to ingest into Tenant Beta -> 403 Forbidden
    res = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "key-alpha-12345"},
        json={
            "tenant_id": "tenant-beta",
            "events": [
                {
                    "event_id": "evt_rogue_1",
                    "agent": "rogue-agent",
                    "tool": "drop_table",
                    "decision": "BLOCK",
                }
            ],
        },
    )
    assert res.status_code == 403
    assert "Cross-tenant access denied" in res.json()["detail"]


def test_telemetry_ingest_and_dashboard_query(telemetry_app):
    client = TestClient(telemetry_app)

    # Ingest 3 real events for tenant-alpha: 1 ALLOW, 1 REVIEW, 1 BLOCK
    batch = [
        {
            "event_id": "evt_alpha_allow",
            "agent": "ops-agent",
            "tool": "read_metrics",
            "decision": "ALLOW",
            "allowed": True,
            "execution_status": "executed",
            "risk_score": 10.0,
            "severity": "LOW",
            "reasons": ["Rule allow read_metrics"],
            "arguments": {"metric": "cpu_usage"},
        },
        {
            "event_id": "evt_alpha_review",
            "agent": "ops-agent",
            "tool": "restart_service",
            "decision": "REVIEW",
            "allowed": False,
            "execution_status": "not_executed",
            "risk_score": 65.0,
            "severity": "MEDIUM",
            "reasons": ["High risk restart requires supervisor review"],
            "arguments": {"service": "web-api"},
        },
        {
            "event_id": "evt_alpha_block",
            "agent": "ops-agent",
            "tool": "delete_database",
            "decision": "BLOCK",
            "allowed": False,
            "execution_status": "not_executed",
            "risk_score": 99.0,
            "severity": "CRITICAL",
            "reasons": ["Destructive actions blocked by default policy"],
            "arguments": {"db": "production_users"},
        },
    ]

    res = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "key-alpha-12345"},
        json={"events": batch},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "accepted"
    assert data["ingested"] == 3
    assert data["duplicates"] == 0
    assert data["tenant_id"] == "tenant-alpha"

    # Query GET /api/events as Tenant Alpha
    events_res = client.get("/api/events", headers={"X-API-Key": "key-alpha-12345"})
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert events_data["total"] == 3
    decisions = {e["tool"]: e["decision"] for e in events_data["events"]}
    assert decisions["read_metrics"] == "ALLOW"
    assert decisions["restart_service"] == "REVIEW"
    assert decisions["delete_database"] == "BLOCK"

    # Query GET /api/overview as Tenant Alpha
    overview_res = client.get("/api/overview", headers={"X-API-Key": "key-alpha-12345"})
    assert overview_res.status_code == 200
    ov = overview_res.json()
    assert ov["total_evaluated"] == 3
    assert ov["allow_count"] == 1
    assert ov["review_count"] == 1
    assert ov["block_count"] == 1

    # Query GET /api/events and /api/overview as Tenant Beta -> 0 events (strictly isolated)
    beta_events = client.get("/api/events", headers={"X-API-Key": "key-beta-67890"})
    assert beta_events.status_code == 200
    assert beta_events.json()["total"] == 0

    beta_overview = client.get("/api/overview", headers={"X-API-Key": "key-beta-67890"})
    assert beta_overview.status_code == 200
    assert beta_overview.json()["total_evaluated"] == 0


def test_telemetry_deduplication(telemetry_app):
    client = TestClient(telemetry_app)

    single_event = {
        "event_id": "evt_dedup_test_1",
        "agent": "worker-bot",
        "tool": "fetch_data",
        "decision": "ALLOW",
        "allowed": True,
        "execution_status": "executed",
    }

    # First send -> ingested: 1, duplicates: 0
    res1 = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "key-alpha-12345"},
        json={"events": [single_event]},
    )
    assert res1.status_code == 200
    assert res1.json()["ingested"] == 1
    assert res1.json()["duplicates"] == 0

    # Second send (client retry of same batch) -> ingested: 0, duplicates: 1
    res2 = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "key-alpha-12345"},
        json={"events": [single_event]},
    )
    assert res2.status_code == 200
    assert res2.json()["ingested"] == 0
    assert res2.json()["duplicates"] == 1

    # Overall count must remain 1
    ov = client.get("/api/overview", headers={"X-API-Key": "key-alpha-12345"}).json()
    assert ov["total_evaluated"] == 1


def test_telemetry_ingest_in_readonly_mode(tmp_path):
    """Verify that read-only mode protects incident controls while allowing telemetry ingestion."""
    audit_db = str(tmp_path / "ro_audit.db")
    app = create_app(
        admin_api_key="admin-key",
        tenant_api_keys={"tenant-ro": "key-ro-1"},
        audit_db_path=audit_db,
        read_only=True,
    )
    client = TestClient(app)

    # 1. Incident control should fail closed with 403 Forbidden
    pause_res = client.post(
        "/api/incident/pause",
        headers={"X-API-Key": "key-ro-1"},
        json={"agent": "some-agent"},
    )
    assert pause_res.status_code == 403
    assert "read-only mode for incident controls" in pause_res.json()["detail"]

    # 2. Telemetry ingestion must succeed so telemetry can be collected in production
    telemetry_res = client.post(
        "/api/v1/telemetry/events",
        headers={"X-API-Key": "key-ro-1"},
        json={
            "events": [
                {
                    "event_id": "evt_ro_1",
                    "agent": "agent-ro",
                    "tool": "read_data",
                    "decision": "ALLOW",
                    "allowed": True,
                    "execution_status": "executed",
                }
            ]
        },
    )
    assert telemetry_res.status_code == 200
    assert telemetry_res.json()["ingested"] == 1

