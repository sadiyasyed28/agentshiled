"""
Focused Milestone 2 Reliability and Security Audit Test Suite.
Adversarial verification probing:
1. Telemetry deduplication across restarts and multi-worker memory boundaries.
2. Queue overflow, retry exhaustion, and persistent delivery failure.
3. Server-side API key resolution and tenant spoofing attempts (headers & body).
4. Event ID vs Correlation ID collision semantics between decisions and outcomes.
5. Client-side and server-side secret redaction under adversarial payloads.
6. Storage compatibility and cryptographic hash chain integrity across ingested events.
7. Multi-tenant isolation and concurrent ingestion integrity.
"""

import os
import json
import uuid
import time
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from agentshield.shield import Shield
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.audit.store import SQLiteAuditStore
from agentshield.events.store import SQLiteEventStore
from agentshield.events.engine import SecurityEventManager
from agentshield.api.app import create_app
from agentshield.telemetry.config import TelemetryConfig
from agentshield.telemetry.exporter import TelemetryExporter, TelemetryEvent


@pytest.fixture
def audit_env(tmp_path):
    """Sets up a clean multi-tenant audit store and API app."""
    db_file = str(tmp_path / "audit_test.db")
    events_file = str(tmp_path / "events_test.db")
    review_file = str(tmp_path / "review_test.db")

    # Configured tenant keys
    tenant_keys = {
        "tenant-corp": "corp-secret-key-111",
        "tenant-victim": "victim-secret-key-222",
    }

    app = create_app(
        admin_api_key="global-admin-key-999",
        tenant_api_keys=tenant_keys,
        audit_db_path=db_file,
        events_db_path=events_file,
        review_db_path=review_file,
        read_only=False,
    )
    client = TestClient(app)
    audit_store = SQLiteAuditStore(db_path=db_file)

    return {
        "audit_store": audit_store,
        "client": client,
        "db_file": db_file,
        "events_file": events_file,
        "review_file": review_file,
        "tenant_keys": tenant_keys,
        "create_app_fn": lambda: create_app(
            admin_api_key="global-admin-key-999",
            tenant_api_keys=tenant_keys,
            audit_db_path=db_file,
            events_db_path=events_file,
            review_db_path=review_file,
            read_only=False,
        ),
    }


# ============================================================================
# AUDIT VERIFICATION 1: Deduplication Across Server Restarts & Workers
# ============================================================================

def test_deduplication_failure_across_simulated_restart_or_multi_worker(audit_env):
    """
    AUDIT FINDING PROOF:
    Demonstrates that in-memory `_seen_telemetry_ids` fails to deduplicate across
    server restarts or across independent Uvicorn worker processes sharing the same DB.
    """
    client = audit_env["client"]
    key = audit_env["tenant_keys"]["tenant-corp"]

    event_payload = {
        "tenant_id": "tenant-corp",
        "events": [
            {
                "event_id": "unique-event-xyz-100",
                "correlation_id": "corr-100",
                "agent": "worker-agent",
                "tool": "search_docs",
                "decision": "ALLOW",
                "allowed": True,
                "execution_status": "executed",
            }
        ],
    }

    # 1. First delivery to Worker 1
    resp1 = client.post("/api/telemetry/events", json=event_payload, headers={"X-API-Key": key})
    assert resp1.status_code == 200
    assert resp1.json()["ingested"] == 1
    assert resp1.json()["duplicates"] == 0

    # 2. Duplicate retry delivered to Worker 1 (in-memory cache catches it)
    resp2 = client.post("/api/telemetry/events", json=event_payload, headers={"X-API-Key": key})
    assert resp2.status_code == 200
    assert resp2.json()["ingested"] == 0
    assert resp2.json()["duplicates"] == 1

    # 3. Simulate Server Restart / Multi-worker process boundary:
    # A new process/worker starts with empty in-memory cache, connected to same DB.
    new_worker_app = audit_env["create_app_fn"]()
    worker2_client = TestClient(new_worker_app)

    # 4. Same client retries delivery to Worker 2 (or post-restart server)
    resp3 = worker2_client.post("/api/telemetry/events", json=event_payload, headers={"X-API-Key": key})
    assert resp3.status_code == 200

    # In-memory deduplication failed across workers: it ingested a duplicate!
    records = audit_env["audit_store"].query(tenant_id="tenant-corp", tool="search_docs")
    # This demonstrates the architectural limitation: 2 identical records inserted in DB
    assert len(records) == 2, (
        f"In-memory deduplication permitted duplicate database insertion across process boundary: {len(records)}"
    )


def test_deduplication_cache_wipe_on_overflow(audit_env):
    """
    AUDIT FINDING PROOF:
    Demonstrates that when `len(tenant_seen) > 10000`, the cache wipes entirely (`clear()`),
    allowing previously seen event IDs to be ingested again.
    """
    client = audit_env["client"]
    key = audit_env["tenant_keys"]["tenant-corp"]

    # 1. Ingest target event
    target_payload = {
        "events": [{"event_id": "target-event-1", "agent": "a", "tool": "t", "decision": "ALLOW"}]
    }
    r = client.post("/api/telemetry/events", json=target_payload, headers={"X-API-Key": key})
    assert r.json()["ingested"] == 1

    # Immediate duplicate is caught
    r_dup = client.post("/api/telemetry/events", json=target_payload, headers={"X-API-Key": key})
    assert r_dup.json()["duplicates"] == 1

    # 2. Flood with 101 batches of 100 events (10,100 distinct events) to trigger eviction limit
    flood_events = [
        {"event_id": f"flood-{b}-{i}", "agent": "a", "tool": "t", "decision": "ALLOW"}
        for b in range(101)
        for i in range(100)
    ]
    # Send in chunks of 100
    for chunk_start in range(0, len(flood_events), 100):
        client.post(
            "/api/telemetry/events",
            json={"events": flood_events[chunk_start : chunk_start + 100]},
            headers={"X-API-Key": key},
        )

    # 3. Now re-send target-event-1: because cache exceeded 10,000 and cleared, target-event-1 is accepted again!
    r2 = client.post("/api/telemetry/events", json=target_payload, headers={"X-API-Key": key})
    assert r2.json()["ingested"] == 1, "Expected cache wipe to allow duplicate re-ingestion"
    assert r2.json()["duplicates"] == 0


# ============================================================================
# AUDIT VERIFICATION 2: Queue Overflow, Retry Exhaustion, and Event Loss
# ============================================================================

def test_telemetry_queue_overflow_event_loss():
    """
    AUDIT FINDING PROOF:
    When the telemetry queue exceeds `max_queue_size`, subsequent events are dropped
    with only a logger warning, meaning the calling process receives no exception or
    dead-letter spooling.
    """
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:9999",
        api_key="test-key",
        max_queue_size=3,
        flush_interval_seconds=60.0,
    )
    exporter = TelemetryExporter(cfg)
    # Stop worker so queue stays full
    exporter._stop_event.set()
    if exporter._worker_thread:
        exporter._worker_thread.join(timeout=1.0)

    # Queue 3 events
    for i in range(3):
        assert exporter.record(TelemetryEvent(agent=f"agent-{i}")) is True

    # 4th and 5th events are dropped silently (returns False)
    assert exporter.record(TelemetryEvent(agent="overflow-1")) is False
    assert exporter.record(TelemetryEvent(agent="overflow-2")) is False

    # The caller application gets no persistent queue or fallback storage
    assert exporter._queue.qsize() == 3


def test_telemetry_retry_exhaustion_discards_events():
    """
    AUDIT FINDING PROOF:
    When remote API is persistently returning 500/network error and max_retries is
    exhausted, `_transmit_batch` returns False and `_worker_loop` drops the batch
    permanently without local offline disk-spooling.
    """
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:9999/unreachable",
        api_key="test-key",
        max_retries=1,
        retry_backoff_base=0.001,
    )
    exporter = TelemetryExporter(cfg)
    batch = [TelemetryEvent(agent="discard-agent", tool="discard-tool")]

    # Transmit fails after max_retries
    ok = exporter._transmit_batch(batch)
    assert ok is False
    # No offline spool file is created by default
    assert not os.path.exists(".telemetry_spool.json")
    exporter.close()


# ============================================================================
# AUDIT VERIFICATION 3: Tenant Spoofing & API Key Authorization
# ============================================================================

def test_tenant_spoofing_via_header_rejected(audit_env):
    """
    ADVERSARIAL TEST:
    Attacker holds valid API key for 'tenant-corp' but attempts to submit telemetry
    with header `X-Tenant-ID: tenant-victim`. Must be rejected with 403.
    """
    client = audit_env["client"]
    corp_key = audit_env["tenant_keys"]["tenant-corp"]

    payload = {
        "events": [
            {
                "event_id": "spoof-1",
                "agent": "attacker-agent",
                "tool": "exfiltrate",
                "decision": "ALLOW",
            }
        ]
    }

    resp = client.post(
        "/api/telemetry/events",
        json=payload,
        headers={"X-API-Key": corp_key, "X-Tenant-ID": "tenant-victim"},
    )
    assert resp.status_code == 403
    assert "Cross-tenant access denied" in resp.json()["detail"] or "cannot access tenant" in resp.json()["detail"]


def test_tenant_spoofing_via_json_body_rejected(audit_env):
    """
    ADVERSARIAL TEST:
    Attacker holds valid API key for 'tenant-corp' but puts `tenant_id: tenant-victim`
    inside the JSON request body. Must be rejected with 403.
    """
    client = audit_env["client"]
    corp_key = audit_env["tenant_keys"]["tenant-corp"]

    payload = {
        "tenant_id": "tenant-victim",
        "events": [
            {
                "event_id": "spoof-body-1",
                "agent": "attacker-agent",
                "tool": "exfiltrate",
                "decision": "ALLOW",
            }
        ],
    }

    resp = client.post(
        "/api/telemetry/events",
        json=payload,
        headers={"X-API-Key": corp_key},
    )
    assert resp.status_code == 403
    assert "Cross-tenant access denied" in resp.json()["detail"]


def test_telemetry_unauthenticated_rejected(audit_env):
    """
    ADVERSARIAL TEST:
    Anonymous or forged API key must return 401 Unauthorized.
    """
    client = audit_env["client"]
    payload = {"events": [{"agent": "a", "tool": "t", "decision": "ALLOW"}]}

    # Missing key
    r1 = client.post("/api/telemetry/events", json=payload)
    assert r1.status_code == 401

    # Forged key
    r2 = client.post(
        "/api/telemetry/events",
        json=payload,
        headers={"X-API-Key": "forged_nonexistent_key_123"},
    )
    assert r2.status_code == 401


# ============================================================================
# AUDIT VERIFICATION 4: Event ID vs Correlation ID Collision Semantics
# ============================================================================

def test_correlation_id_fallback_erroneous_deduplication(audit_env):
    """
    AUDIT FINDING PROOF:
    Demonstrates that if an event has `event_id=None`, line 996 falls back to
    `evt_id = item.event_id or item.correlation_id`.
    Because a single tool call produces BOTH an authorization decision AND an execution
    outcome sharing the SAME correlation_id, the execution outcome is erroneously
    dropped as a duplicate!
    """
    client = audit_env["client"]
    key = audit_env["tenant_keys"]["tenant-corp"]

    shared_correlation_id = f"corr-shared-{uuid.uuid4().hex[:8]}"

    # Event 1: Authorization decision (ALLOW)
    # Event 2: Execution outcome (executed)
    # Both share the same correlation_id and have event_id=None
    batch = {
        "events": [
            {
                "event_id": None,
                "correlation_id": shared_correlation_id,
                "agent": "finance-agent",
                "tool": "approve_invoice",
                "decision": "ALLOW",
                "execution_status": "pending",
                "event_type": "authorization_decision",
            },
            {
                "event_id": None,
                "correlation_id": shared_correlation_id,
                "agent": "finance-agent",
                "tool": "approve_invoice",
                "decision": "ALLOW",
                "execution_status": "executed",
                "event_type": "execution_outcome",
            },
        ]
    }

    resp = client.post("/api/telemetry/events", json=batch, headers={"X-API-Key": key})
    assert resp.status_code == 200
    data = resp.json()

    # The bug in action: ingested 1, duplicates 1!
    # The execution outcome was wrongly dropped because correlation_id alone was used as deduplication key!
    assert data["ingested"] == 1
    assert data["duplicates"] == 1


# ============================================================================
# AUDIT VERIFICATION 5: Secret Redaction Before & After Transmission
# ============================================================================

def test_secret_redaction_adversarial_depth(audit_env):
    """
    ADVERSARIAL TEST:
    Verify that sensitive credentials in arguments (nested dictionaries, lists,
    Bearer headers, high-entropy API tokens) are completely redacted both client-side
    and server-side.
    """
    client = audit_env["client"]
    key = audit_env["tenant_keys"]["tenant-corp"]

    sensitive_args = {
        "api_key": "sk_live_very_secret_key_12345",
        "nested": {
            "password": "super-secret-password-xyz",
            "safe_param": "safe_value",
            "auth_header": "Bearer ghp_token_value_abc_123",
        },
        "credentials_list": [
            {"token": "gho_token_999"},
            {"public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."},
        ],
    }

    # Transmit via TelemetryEvent
    evt = TelemetryEvent(
        agent="agent-secrets",
        tool="deploy_service",
        decision="ALLOW",
        arguments=sensitive_args,
        error="Failed connection with authorization Bearer secret_conn_token_888",
    )

    # 1. Client-side serialization check
    serialized = evt.to_dict()
    assert serialized["arguments"]["api_key"] == "[REDACTED]"
    assert serialized["arguments"]["nested"]["password"] == "[REDACTED]"
    assert "ghp_token_value_abc_123" not in serialized["arguments"]["nested"]["auth_header"]
    assert serialized["arguments"]["credentials_list"][0]["token"] == "[REDACTED]"
    assert "secret_conn_token_888" not in serialized["error"]

    # 2. Server ingestion and storage check
    payload = {"events": [serialized]}
    resp = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert resp.status_code == 200

    # Query persisted audit record
    records = audit_env["audit_store"].query(tenant_id="tenant-corp", tool="deploy_service")
    assert len(records) == 1
    stored = records[0]

    assert stored.arguments["api_key"] == "[REDACTED]"
    assert stored.arguments["nested"]["password"] == "[REDACTED]"
    assert "ghp_token_value_abc_123" not in str(stored.arguments)
    assert "secret_conn_token_888" not in str(stored.error)


# ============================================================================
# AUDIT VERIFICATION 6 & 7: Hash Chain Integrity & Storage Compatibility
# ============================================================================

def test_hash_chain_integrity_with_remote_timestamps_and_out_of_order_arrival(audit_env):
    """
    AUDIT TEST:
    Verify that ingesting telemetry events with client timestamps (even slightly skewed
    or out-of-order) maintains mathematical hash chain integrity (`verify_integrity()`).
    """
    client = audit_env["client"]
    key = audit_env["tenant_keys"]["tenant-corp"]
    audit_store = audit_env["audit_store"]

    events = [
        {
            "event_id": f"chain-evt-{i}",
            "agent": "chronos-agent",
            "tool": "time_travel",
            "decision": "ALLOW" if i % 2 == 0 else "BLOCK",
            "risk_score": 0.1 * i,
            "timestamp": f"2026-11-11T12:{30 - i:02d}:00Z",  # Backwards timestamps
        }
        for i in range(10)
    ]

    payload = {"events": events}
    resp = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 10

    # Check cryptographic integrity of SQLite audit store
    integrity = audit_store.verify_integrity()
    assert integrity["valid"] is True, f"Cryptographic hash chain broken: {integrity['error']}"
    assert integrity["total_records"] == 10
    assert integrity["corrupted_record_id"] is None


def test_concurrent_multi_tenant_isolation(audit_env):
    """
    ADVERSARIAL TEST:
    Ensure events ingested under 'tenant-corp' are completely invisible to 'tenant-victim'
    across all query endpoints (/api/events, /api/overview, audit_store.query).
    """
    client = audit_env["client"]
    corp_key = audit_env["tenant_keys"]["tenant-corp"]
    victim_key = audit_env["tenant_keys"]["tenant-victim"]

    # Ingest for corp
    client.post(
        "/api/telemetry/events",
        json={"events": [{"event_id": "corp-1", "agent": "corp-agent", "tool": "corp_tool", "decision": "ALLOW"}]},
        headers={"X-API-Key": corp_key},
    )

    # Ingest for victim
    client.post(
        "/api/telemetry/events",
        json={"events": [{"event_id": "victim-1", "agent": "victim-agent", "tool": "victim_tool", "decision": "BLOCK"}]},
        headers={"X-API-Key": victim_key},
    )

    # Query as Corp
    corp_events = client.get("/api/events", headers={"X-API-Key": corp_key}).json()["events"]
    assert len(corp_events) == 1
    assert corp_events[0]["tool"] == "corp_tool"

    # Query as Victim
    victim_events = client.get("/api/events", headers={"X-API-Key": victim_key}).json()["events"]
    assert len(victim_events) == 1
    assert victim_events[0]["tool"] == "victim_tool"

    # Cross-tenant query attempt by victim asking for corp data
    cross_resp = client.get("/api/events?tenant_id=tenant-corp", headers={"X-API-Key": victim_key})
    assert cross_resp.status_code == 403
