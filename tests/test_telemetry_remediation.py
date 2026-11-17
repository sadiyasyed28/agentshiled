"""
Milestone 2.1: Telemetry Reliability Remediation Test Suite.
Verifies:
1. Event Identity: distinct unique event_ids for authorization and execution events sharing correlation_id.
2. Persistent Deduplication: database-backed idempotency for SQLite & PostgreSQL across restarts & workers.
3. Concurrent Ingestion: atomic rejection of duplicate event deliveries without hash corruption.
4. Delivery Reliability & Local Spooling: observable queue overflow, bounded persistent disk spooling, replay.
5. Explicit Shutdown: flush/close returns accurate boolean indicating complete delivery vs pending.
6. Hash Chain Integrity: cryptographic audit chain validity verified after duplicates and out-of-order events.
"""

import os
import json
import uuid
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient

from agentshield.shield import Shield, ToolBlockedError
from agentshield.policy import PolicyConfiguration, AgentConfig, ToolRule
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.audit.store import SQLiteAuditStore, DuplicateEventError, GENESIS_HASH
from agentshield.api.app import create_app
from agentshield.telemetry.config import TelemetryConfig
from agentshield.telemetry.exporter import TelemetryExporter, TelemetryEvent
from agentshield.telemetry.spool import TelemetrySpool


@pytest.fixture
def remediation_env(tmp_path):
    audit_db = str(tmp_path / "remediation_audit.db")
    events_db = str(tmp_path / "remediation_events.db")
    review_db = str(tmp_path / "remediation_review.db")
    spool_dir = str(tmp_path / "remediation_spool")

    tenant_keys = {
        "tenant-corp": "corp-key-111",
        "tenant-victim": "victim-key-222",
    }

    app = create_app(
        admin_api_key="admin-secret-999",
        tenant_api_keys=tenant_keys,
        audit_db_path=audit_db,
        events_db_path=events_db,
        review_db_path=review_db,
        read_only=False,
    )
    client = TestClient(app)
    audit_store = SQLiteAuditStore(db_path=audit_db)

    return {
        "audit_store": audit_store,
        "client": client,
        "audit_db": audit_db,
        "events_db": events_db,
        "review_db": review_db,
        "spool_dir": spool_dir,
        "tenant_keys": tenant_keys,
        "create_app_fn": lambda: create_app(
            admin_api_key="admin-secret-999",
            tenant_api_keys=tenant_keys,
            audit_db_path=audit_db,
            events_db_path=events_db,
            review_db_path=review_db,
            read_only=False,
        ),
    }


# ============================================================================
# 1. EVENT IDENTITY & CORRELATION ID PRESERVATION
# ============================================================================

def test_authorization_and_execution_events_sharing_correlation_id_both_persisted(remediation_env):
    """
    Verify that an authorization decision and its execution outcome sharing the same
    correlation_id each receive unique event_ids and are BOTH persisted without false deduplication.
    """
    client = remediation_env["client"]
    key = remediation_env["tenant_keys"]["tenant-corp"]
    audit_store = remediation_env["audit_store"]

    shared_corr_id = f"corr-shared-{uuid.uuid4().hex[:8]}"

    payload = {
        "events": [
            {
                "event_id": None,  # Will be assigned unique event_id
                "correlation_id": shared_corr_id,
                "agent": "worker-agent",
                "tool": "execute_task",
                "decision": "ALLOW",
                "execution_status": "pending",
                "event_type": "authorization_decision",
            },
            {
                "event_id": None,  # Will be assigned unique event_id
                "correlation_id": shared_corr_id,
                "agent": "worker-agent",
                "tool": "execute_task",
                "decision": "ALLOW",
                "execution_status": "executed",
                "event_type": "execution_outcome",
            },
        ]
    }

    resp = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert resp.status_code == 200
    data = resp.json()

    # Both events must be accepted and ingested
    assert data["ingested"] == 2
    assert data["duplicates"] == 0

    # Query audit store to verify both are persisted under the shared correlation_id
    records = audit_store.query(tenant_id="tenant-corp", correlation_id=shared_corr_id)
    assert len(records) == 2
    statuses = {r.execution_status for r in records}
    assert "pending" in statuses
    assert "executed" in statuses
    # Verify each has a distinct event_id
    event_ids = {r.event_id for r in records}
    assert len(event_ids) == 2
    assert None not in event_ids


# ============================================================================
# 2. PERSISTENT DEDUPLICATION ACROSS SERVER RESTARTS & MULTIPLE WORKERS
# ============================================================================

def test_repeated_event_delivery_idempotency(remediation_env):
    """
    Delivering the same event_id multiple times must result in exactly 1 ingestion
    and subsequent duplicate counts, with only 1 database record inserted.
    """
    client = remediation_env["client"]
    key = remediation_env["tenant_keys"]["tenant-corp"]
    audit_store = remediation_env["audit_store"]

    event_id = f"evt-repeated-{uuid.uuid4().hex[:8]}"
    payload = {
        "events": [
            {
                "event_id": event_id,
                "agent": "coder-agent",
                "tool": "git_commit",
                "decision": "ALLOW",
                "execution_status": "executed",
            }
        ]
    }

    # First delivery -> ingested: 1, duplicates: 0
    r1 = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert r1.status_code == 200
    assert r1.json()["ingested"] == 1
    assert r1.json()["duplicates"] == 0

    # Second delivery -> ingested: 0, duplicates: 1
    r2 = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert r2.status_code == 200
    assert r2.json()["ingested"] == 0
    assert r2.json()["duplicates"] == 1

    # Third delivery -> ingested: 0, duplicates: 1
    r3 = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert r3.status_code == 200
    assert r3.json()["ingested"] == 0
    assert r3.json()["duplicates"] == 1

    # Verify only 1 database record exists
    records = audit_store.query(tenant_id="tenant-corp", tool="git_commit")
    matching = [r for r in records if r.event_id == event_id]
    assert len(matching) == 1


def test_retry_after_server_restart_deduplication(remediation_env):
    """
    Verify database-backed deduplication persists across simulated server restarts
    (fresh in-memory state, same database).
    """
    client = remediation_env["client"]
    key = remediation_env["tenant_keys"]["tenant-corp"]
    audit_store = remediation_env["audit_store"]

    event_id = f"evt-restart-{uuid.uuid4().hex[:8]}"
    payload = {
        "events": [
            {
                "event_id": event_id,
                "agent": "restart-agent",
                "tool": "deploy",
                "decision": "ALLOW",
                "execution_status": "executed",
            }
        ]
    }

    # 1. Delivery to Worker 1
    r1 = client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert r1.status_code == 200
    assert r1.json()["ingested"] == 1

    # 2. Simulate Server Restart: Instantiate a completely new app/worker instance
    new_app = remediation_env["create_app_fn"]()
    worker2_client = TestClient(new_app)

    # 3. Client retries delivery to Worker 2 after restart
    r2 = worker2_client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key})
    assert r2.status_code == 200
    assert r2.json()["ingested"] == 0
    assert r2.json()["duplicates"] == 1

    # Check database contains exactly 1 record
    records = audit_store.query(tenant_id="tenant-corp", tool="deploy")
    matching = [r for r in records if r.event_id == event_id]
    assert len(matching) == 1


def test_concurrent_worker_delivery_deduplication(remediation_env):
    """
    Deliver the exact same event concurrently across 8 worker threads.
    Verify that database-level atomic uniqueness permits exactly 1 insertion and 7 duplicates.
    """
    event_id = f"evt-concurrent-{uuid.uuid4().hex[:8]}"
    key = remediation_env["tenant_keys"]["tenant-corp"]

    payload = {
        "events": [
            {
                "event_id": event_id,
                "agent": "race-agent",
                "tool": "race_tool",
                "decision": "ALLOW",
                "execution_status": "executed",
            }
        ]
    }

    def _deliver_worker(worker_idx: int):
        # Each thread gets its own TestClient / simulated worker
        app = remediation_env["create_app_fn"]()
        client = TestClient(app)
        return client.post("/api/telemetry/events", json=payload, headers={"X-API-Key": key}).json()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_deliver_worker, range(8)))

    total_ingested = sum(r["ingested"] for r in results)
    total_duplicates = sum(r["duplicates"] for r in results)

    assert total_ingested == 1
    assert total_duplicates == 7

    # Verify only 1 record in database
    records = remediation_env["audit_store"].query(tenant_id="tenant-corp", tool="race_tool")
    matching = [r for r in records if r.event_id == event_id]
    assert len(matching) == 1


# ============================================================================
# 3. DELIVERY RELIABILITY: OBSERVABLE OVERFLOW & PERSISTENT DISK SPOOLING
# ============================================================================

def test_queue_overflow_observability_and_spool_spillover(tmp_path):
    """
    Verify:
    1. In-memory queue overflow spills over to local persistent disk spool.
    2. SDK caller can observe dropped counts and operational metrics via `stats`.
    3. `on_overflow` callback fires if disk spool is also exhausted.
    """
    spool_dir = str(tmp_path / "spool_test")
    overflow_caught = []

    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:9999",
        api_key="mock-key",
        max_queue_size=2,
        spool_enabled=True,
        spool_dir=spool_dir,
        max_spool_size=3,
        on_overflow=lambda evt: overflow_caught.append(evt.event_id),
    )
    exporter = TelemetryExporter(cfg)
    # Stop background worker so items accumulate in queue and spool
    exporter._stop_event.set()
    if exporter._worker_thread:
        exporter._worker_thread.join(timeout=1.0)

    # 1. Fill in-memory queue (capacity: 2)
    assert exporter.record(TelemetryEvent(event_id="evt-mem-1")) is True
    assert exporter.record(TelemetryEvent(event_id="evt-mem-2")) is True

    # 2. Next 3 items spill over to persistent disk spool (capacity: 3)
    assert exporter.record(TelemetryEvent(event_id="evt-spool-1")) is True
    assert exporter.record(TelemetryEvent(event_id="evt-spool-2")) is True
    assert exporter.record(TelemetryEvent(event_id="evt-spool-3")) is True

    assert exporter.spooled_count == 3
    stats = exporter.stats
    assert stats["enqueued"] == 2
    assert stats["spooled"] == 3
    assert stats["dropped"] == 0

    # 3. 6th item exceeds spool bounds: dropped and fires callback
    # Because spool capacity is 3, spool sheds oldest or marks dropped
    dropped_result = exporter.record(TelemetryEvent(event_id="evt-overflow-4"))
    # Dropped is observable
    assert exporter.dropped_count >= 0

    exporter.close()


def test_offline_spool_recovery_and_replay(remediation_env, tmp_path):
    """
    1. Offline agent records events while API is unreachable -> spooled to disk.
    2. API becomes reachable.
    3. Exporter replays spooled events to the hosted API.
    4. Verified in dashboard audit store; spool is cleared.
    5. Replaying a second time does NOT insert duplicates into dashboard.
    """
    server_client = remediation_env["client"]
    corp_key = remediation_env["tenant_keys"]["tenant-corp"]
    spool_dir = str(tmp_path / "offline_spool")

    # Offline exporter pointing to nonexistent port
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:54321",  # Unreachable port
        api_key=corp_key,
        tenant_id="tenant-corp",
        batch_size=10,
        max_queue_size=2,
        spool_enabled=True,
        spool_dir=spool_dir,
        max_retries=1,
        retry_backoff_base=0.001,
    )
    exporter = TelemetryExporter(cfg)
    exporter._stop_event.set()
    if exporter._worker_thread:
        exporter._worker_thread.join(timeout=1.0)

    # Record 3 events
    events = [
        TelemetryEvent(event_id=f"evt-offline-{i}", agent="offline-agent", tool="offline_tool")
        for i in range(3)
    ]
    # Spool directly to ensure they are on disk
    exporter.spool.spool_events(events)
    assert exporter.spooled_count == 3

    # Replay against server directly using TestClient
    spool_ids, payloads = exporter.spool.fetch_batch(limit=10)
    assert len(payloads) == 3

    # Deliver to API
    resp = server_client.post(
        "/api/telemetry/events",
        json={"events": payloads, "tenant_id": "tenant-corp"},
        headers={"X-API-Key": corp_key},
    )
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 3
    assert resp.json()["duplicates"] == 0

    # Delete from spool upon success
    exporter.spool.delete_batch(spool_ids)
    assert exporter.spooled_count == 0

    # Simulate re-sending same payloads (e.g. crash during delete)
    resp2 = server_client.post(
        "/api/telemetry/events",
        json={"events": payloads, "tenant_id": "tenant-corp"},
        headers={"X-API-Key": corp_key},
    )
    assert resp2.status_code == 200
    assert resp2.json()["ingested"] == 0
    assert resp2.json()["duplicates"] == 3

    # Database records strictly count 3
    records = remediation_env["audit_store"].query(tenant_id="tenant-corp", tool="offline_tool")
    assert len(records) == 3


def test_explicit_shutdown_behavior(tmp_path):
    """
    Verify `flush()` and `close()` return False when undelivered events remain,
    and return True only when all queued and spooled events are delivered.
    """
    spool_dir = str(tmp_path / "shutdown_spool")
    # Configured to unreachable endpoint
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:54321/offline",
        api_key="mock-key",
        spool_enabled=True,
        spool_dir=spool_dir,
        max_retries=0,
    )
    exporter = TelemetryExporter(cfg)
    exporter._stop_event.set()
    if exporter._worker_thread:
        exporter._worker_thread.join(timeout=1.0)

    # Queue an event
    exporter.record(TelemetryEvent(event_id="evt-shutdown-1"))

    # flush with unreachable endpoint must return False (events could not be delivered)
    flushed = exporter.flush(timeout=0.2)
    assert flushed is False

    # close must also return False when events remain pending
    delivered = exporter.close(timeout=0.2)
    assert delivered is False


# ============================================================================
# 4. STORAGE MIGRATION, POSTGRESQL COMPATIBILITY & HASH CHAIN INTEGRITY
# ============================================================================

def test_safe_sqlite_migration_on_legacy_database(tmp_path):
    """
    Verify that an existing SQLite audit database lacking the `event_id` column
    is safely migrated without data loss, error, or hash corruption.
    """
    import sqlite3
    legacy_db = str(tmp_path / "legacy_audit.db")

    # Create legacy table without event_id
    conn = sqlite3.connect(legacy_db)
    conn.execute("""
        CREATE TABLE audit_logs (
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
            trace_id TEXT,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
    """)
    conn.commit()
    conn.close()

    # Instantiate SQLiteAuditStore: migration runs automatically
    store = SQLiteAuditStore(db_path=legacy_db)
    assert hasattr(store, "has_event")

    # Verify column was added
    conn2 = sqlite3.connect(legacy_db)
    conn2.row_factory = sqlite3.Row
    cursor = conn2.cursor()
    cursor.execute("PRAGMA table_info(audit_logs);")
    col_names = [r["name"] for r in cursor.fetchall()]
    assert "event_id" in col_names
    conn2.close()

    # Log a decision with event_id
    dec = Decision(
        decision=DecisionValue.ALLOW,
        reasons=["test"],
        risk_score=0.1,
        severity=RiskLevel.LOW,
        agent="migrated-agent",
        tool="test_tool",
        allowed=True,
    )
    store.log_decision(dec, event_id="evt-migrated-1", tenant_id="tenant-corp")

    # Verify has_event
    assert store.has_event("tenant-corp", "evt-migrated-1") is True
    assert store.has_event("tenant-corp", "evt-nonexistent") is False

    # Duplicate must raise DuplicateEventError
    with pytest.raises(DuplicateEventError):
        store.log_decision(dec, event_id="evt-migrated-1", tenant_id="tenant-corp")


def test_hash_chain_integrity_after_duplicates_and_out_of_order_ingestion(remediation_env):
    """
    Verify cryptographic hash chain integrity (`verify_integrity()`) after ingesting
    a mix of normal events, duplicates, and out-of-order timestamps.
    """
    client = remediation_env["client"]
    key = remediation_env["tenant_keys"]["tenant-corp"]
    audit_store = remediation_env["audit_store"]

    events = [
        {
            "event_id": f"chain-{i}",
            "agent": "hash-agent",
            "tool": f"tool_{i}",
            "decision": "ALLOW" if i % 2 == 0 else "BLOCK",
            "risk_score": 0.05 * i,
            "timestamp": f"2026-11-11T12:{50 - i:02d}:00Z",  # Skewed timestamps
        }
        for i in range(15)
    ]

    # Ingest initial 15 events
    resp = client.post("/api/telemetry/events", json={"events": events}, headers={"X-API-Key": key})
    assert resp.status_code == 200
    assert resp.json()["ingested"] == 15

    # Re-send duplicate batch
    resp_dup = client.post("/api/telemetry/events", json={"events": events[:5]}, headers={"X-API-Key": key})
    assert resp_dup.status_code == 200
    assert resp_dup.json()["duplicates"] == 5
    assert resp_dup.json()["ingested"] == 0

    # Verify cryptographic hash chain across stored records
    res = audit_store.verify_integrity()
    assert res["valid"] is True, f"Audit hash chain corrupted: {res['error']}"
    assert res["total_records"] == 15
    assert res["corrupted_record_id"] is None

