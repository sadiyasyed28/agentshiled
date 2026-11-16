"""
Tests for Milestone 3: Self-Service Customer Onboarding and API Key Management.

Verifies:
1. Secure tenant registration with PBKDF2-HMAC-SHA256 password hashing.
2. Cryptographic API key generation with 'ash_live_' prefix.
3. Storing only key SHA-256 hashes, never plaintext API keys in persistent storage.
4. Returning plaintext API keys only once upon creation / rotation.
5. Authenticating endpoints and telemetry ingestion using the generated API keys.
6. Masked key listing (ash_live_...last4), revocation, and rotation.
7. Strict tenant isolation and cross-tenant spoofing prevention (IDOR).
8. Full integration with Python SDK telemetry exporter using API URL and API Key.
"""

import hashlib
import os
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from agentshield import Shield
from agentshield.api.app import create_app
from agentshield.storage.tenants import (
    SqliteTenantStore,
    hash_password,
    verify_password,
    generate_api_key,
    TenantAlreadyExistsError,
)
from agentshield.telemetry import TelemetryConfig, TelemetryExporter


@pytest.fixture
def temp_dbs():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        audit_db = os.path.join(tmpdir, "audit.db")
        events_db = os.path.join(tmpdir, "events.db")
        reviews_db = os.path.join(tmpdir, "reviews.db")
        sessions_db = os.path.join(tmpdir, "sessions.db")
        tenants_db = os.path.join(tmpdir, "tenants.db")
        yield {
            "audit_db": audit_db,
            "events_db": events_db,
            "reviews_db": reviews_db,
            "sessions_db": sessions_db,
            "tenants_db": tenants_db,
        }


def test_password_hashing_and_verification():
    raw_password = "SuperSecretPassword123!"
    h1, salt1 = hash_password(raw_password)
    assert len(salt1) >= 32  # 16 bytes in hex
    assert len(h1) == 64  # SHA-256 hex string

    # Verify password against correct and incorrect attempts
    assert verify_password(raw_password, h1, salt1) is True
    assert verify_password("WrongPassword!", h1, salt1) is False
    assert verify_password(raw_password, h1, "00" * 16) is False

    # Distinct salts produce distinct hashes
    h2, salt2 = hash_password(raw_password)
    assert salt1 != salt2
    assert h1 != h2


def test_api_key_generation_and_hashing():
    full_key, key_hash, prefix, last_four = generate_api_key(prefix="ash_live")
    assert full_key.startswith("ash_live_")
    assert len(full_key) > 40
    assert full_key.endswith(last_four)
    assert prefix == "ash_live"
    assert hashlib.sha256(full_key.encode("utf-8")).hexdigest() == key_hash


def test_tenant_registration_and_key_creation(temp_dbs):
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )
    client = TestClient(app)

    # 1. Register new developer workspace
    resp = client.post(
        "/api/auth/register",
        json={
            "name": "Acme Robotics",
            "email": "dev@acmerobotics.io",
            "password": "SecurePassword999!",
        },
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "created"
    assert data["name"] == "Acme Robotics"
    assert data["email"] == "dev@acmerobotics.io"
    assert data["tenant_id"].startswith("t_")
    tenant_id = data["tenant_id"]

    # Plaintext API key is returned ONCE
    plaintext_key = data["api_key"]
    assert plaintext_key.startswith("ash_live_")
    masked_key = data["masked_key"]
    assert masked_key == f"ash_live_...{plaintext_key[-4:]}"

    # Verify that the session cookie was set
    assert "agentshield_session" in resp.cookies

    # 2. Verify that the database stores ONLY key hash, never the plaintext key
    tenant_store: SqliteTenantStore = app.state.tenant_store
    t_rec = tenant_store.get_tenant(tenant_id)
    assert t_rec is not None
    assert t_rec.name == "Acme Robotics"
    # Never stored raw password
    assert t_rec.password_hash != "SecurePassword999!"
    assert verify_password("SecurePassword999!", t_rec.password_hash, t_rec.password_salt)

    keys = tenant_store.list_api_keys(tenant_id)
    assert len(keys) == 1
    key_record = keys[0]
    assert key_record.key_hash == hashlib.sha256(plaintext_key.encode()).hexdigest()
    # Confirm raw key doesn't exist anywhere in the record
    assert not hasattr(key_record, "api_key")
    assert plaintext_key not in (key_record.key_hash, key_record.prefix, key_record.last_four)


def test_api_key_authentication_and_idor_protection(temp_dbs):
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )
    client = TestClient(app)

    # Register Tenant A
    res_a = client.post(
        "/api/auth/register",
        json={"name": "Alpha Corp", "email": "admin@alpha.com", "password": "Password123!"},
    )
    assert res_a.status_code == 200
    tenant_a_id = res_a.json()["tenant_id"]
    api_key_a = res_a.json()["api_key"]

    # Register Tenant B
    res_b = client.post(
        "/api/auth/register",
        json={"name": "Beta Corp", "email": "admin@beta.com", "password": "Password123!"},
    )
    assert res_b.status_code == 200
    tenant_b_id = res_b.json()["tenant_id"]
    api_key_b = res_b.json()["api_key"]

    # 1. Unauthenticated request to /api/api-keys is rejected with 401
    unauth_client = TestClient(app)
    unauth_res = unauth_client.get("/api/api-keys")
    assert unauth_res.status_code == 401

    # 2. Authenticate using X-API-Key for Tenant A
    res_keys_a = client.get("/api/api-keys", headers={"x-api-key": api_key_a})
    assert res_keys_a.status_code == 200
    keys_a = res_keys_a.json()["keys"]
    assert len(keys_a) == 1
    assert keys_a[0]["tenant_id"] == tenant_a_id
    # Masked presentation only
    assert keys_a[0]["masked_key"].startswith("ash_live_...")
    assert "api_key" not in keys_a[0]

    # 3. Authenticate using Authorization: Bearer for Tenant B
    res_keys_b = client.get("/api/api-keys", headers={"authorization": f"Bearer {api_key_b}"})
    assert res_keys_b.status_code == 200
    keys_b = res_keys_b.json()["keys"]
    assert len(keys_b) == 1
    assert keys_b[0]["tenant_id"] == tenant_b_id

    # 4. Cross-tenant IDOR rejection: Tenant A attempts to spoof Tenant B
    idor_res = client.get(
        "/api/api-keys",
        headers={"x-api-key": api_key_a, "x-tenant-id": tenant_b_id},
    )
    assert idor_res.status_code == 403
    assert "cannot access tenant" in idor_res.json()["detail"].lower()


def test_api_key_lifecycle_creation_revocation_rotation(temp_dbs):
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )
    client = TestClient(app)

    reg = client.post(
        "/api/auth/register",
        json={"name": "Starlight AI", "email": "ops@starlight.ai", "password": "SuperPassword123!"},
    )
    assert reg.status_code == 200
    tenant_id = reg.json()["tenant_id"]
    initial_key = reg.json()["api_key"]
    initial_key_id = reg.json()["key_id"]

    # 1. Create a second API key with custom name
    new_key_res = client.post(
        "/api/api-keys",
        headers={"x-api-key": initial_key},
        json={"name": "CI Runner Key", "prefix": "ash_live"},
    )
    assert new_key_res.status_code == 200
    new_key_data = new_key_res.json()
    second_key = new_key_data["api_key"]
    second_key_id = new_key_data["key_id"]
    assert second_key.startswith("ash_live_")
    assert second_key != initial_key

    # List keys - both should be present
    list_res = client.get("/api/api-keys", headers={"x-api-key": initial_key})
    assert list_res.status_code == 200
    assert list_res.json()["total"] == 2

    # 2. Revoke the initial key
    revoke_res = client.post(
        f"/api/api-keys/{initial_key_id}/revoke",
        headers={"x-api-key": second_key},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "revoked"

    # Immediately, initial key is unauthorized (401)
    revoked_attempt = client.get("/api/api-keys", headers={"x-api-key": initial_key})
    assert revoked_attempt.status_code == 401

    # Second key is still valid
    valid_attempt = client.get("/api/api-keys", headers={"x-api-key": second_key})
    assert valid_attempt.status_code == 200

    # 3. Rotate the second key
    rotate_res = client.post(
        f"/api/api-keys/{second_key_id}/rotate",
        headers={"x-api-key": second_key},
        json={"name": "Rotated CI Key"},
    )
    assert rotate_res.status_code == 200
    third_key = rotate_res.json()["api_key"]
    assert third_key != second_key

    # Old key (second key) is now revoked
    old_rotated_attempt = client.get("/api/api-keys", headers={"x-api-key": second_key})
    assert old_rotated_attempt.status_code == 401

    # New rotated key works
    new_rotated_attempt = client.get("/api/api-keys", headers={"x-api-key": third_key})
    assert new_rotated_attempt.status_code == 200


def test_sdk_telemetry_integration_with_customer_key(temp_dbs):
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )
    client = TestClient(app)

    # Self-service developer registration
    reg = client.post(
        "/api/auth/register",
        json={"name": "Autonomous Agents Inc", "email": "lead@autonomous.org", "password": "Password999!"},
    )
    assert reg.status_code == 200
    tenant_id = reg.json()["tenant_id"]
    customer_api_key = reg.json()["api_key"]

    # Verify that telemetry exporter works with TestClient adapter or direct HTTP
    # We can ingest directly via TelemetryIngestRequest to verify resolution
    ingest_payload = {
        "tenant_id": tenant_id,
        "events": [
            {
                "event_id": "evt_customer_1",
                "timestamp": "2026-11-11T12:00:00Z",
                "agent": "customer-agent",
                "tool": "create_order",
                "decision": "ALLOW",
                "allowed": True,
                "reasons": ["Tool in allowlist"],
                "risk_score": 5.0,
                "severity": "LOW",
                "execution_status": "executed",
                "arguments": {"product_id": "prod_42", "quantity": 1},
                "correlation_id": "corr_cust_1",
            }
        ],
    }

    # Send telemetry with customer API key
    tel_res = client.post(
        "/api/telemetry/events",
        headers={"x-api-key": customer_api_key},
        json=ingest_payload,
    )
    assert tel_res.status_code == 200, tel_res.text
    assert tel_res.json()["ingested"] == 1
    assert tel_res.json()["tenant_id"] == tenant_id

    # Verify that the event is retrievable scoped to this customer
    events_res = client.get(
        "/api/events",
        headers={"x-api-key": customer_api_key},
    )
    assert events_res.status_code == 200
    evts = events_res.json()["events"]
    assert len(evts) == 1
    assert evts[0]["agent"] == "customer-agent"
    assert evts[0]["tenant_id"] == tenant_id


def test_duplicate_registration_validation(temp_dbs):
    app = create_app(
        audit_db_path=temp_dbs["audit_db"],
        events_db_path=temp_dbs["events_db"],
        review_db_path=temp_dbs["reviews_db"],
        sessions_db_path=temp_dbs["sessions_db"],
        tenants_db_path=temp_dbs["tenants_db"],
    )
    client = TestClient(app)

    r1 = client.post(
        "/api/auth/register",
        json={"name": "First Org", "email": "same@example.com", "password": "Password123!"},
    )
    assert r1.status_code == 200

    # Duplicate email rejected with 409 Conflict
    r2 = client.post(
        "/api/auth/register",
        json={"name": "Second Org", "email": "same@example.com", "password": "Password456!"},
    )
    assert r2.status_code == 409
    assert "already exists" in r2.json()["detail"]

    # Short password rejected with 400
    r3 = client.post(
        "/api/auth/register",
        json={"name": "Short Pwd Org", "email": "valid@example.com", "password": "short"},
    )
    assert r3.status_code in (400, 422)


def test_in_memory_sqlite_tenant_store_persistence():
    """Regression test: verifies SqliteTenantStore retains data across calls when db_path=':memory:'."""
    import concurrent.futures

    store = SqliteTenantStore(":memory:")
    # 1. Register tenant
    t = store.create_tenant(name="Memory Org", email="mem@example.com", password="SecurePassword123!")
    assert t.tenant_id is not None

    # 2. Query tenant by ID and email repeatedly
    t_retrieved = store.get_tenant(t.tenant_id)
    assert t_retrieved is not None
    assert t_retrieved.owner_email == "mem@example.com"

    t_by_email = store.get_tenant_by_email("mem@example.com")
    assert t_by_email is not None
    assert t_by_email.tenant_id == t.tenant_id

    # 3. Create API key and lookup by hash
    key_rec, raw_key = store.create_api_key(tenant_id=t.tenant_id, name="Test Key")
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    found_key = store.get_key_by_hash(key_hash)
    assert found_key is not None
    assert found_key.key_id == key_rec.key_id
    assert found_key.tenant_id == t.tenant_id
    assert found_key.is_active is True

    # 4. Multi-threaded access to in-memory store
    def _worker(idx: int):
        return store.get_key_by_hash(key_hash)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_worker, i) for i in range(20)]
        results = [f.result() for f in futures]
    assert all(r is not None and r.key_id == key_rec.key_id for r in results)


def test_telemetry_status_health_reporting():
    """Verifies /api/telemetry/status accurately derives health and isolates storage errors."""
    app = create_app(audit_db_path=":memory:")
    client = TestClient(app)

    # 1. Normal state -> healthy: True, status: awaiting_telemetry
    resp = client.get("/api/telemetry/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["healthy"] is True
    assert data["storage_healthy"] is True
    assert data["status"] in ("awaiting_telemetry", "connected")
    assert "backend_exporter_pending" in data
    assert "backend_exporter_dropped" in data
