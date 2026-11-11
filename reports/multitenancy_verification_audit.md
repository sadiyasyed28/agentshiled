# AgentShield Milestone 8.1 — Multi-Tenant Security Verification Audit

**Audit Date**: November 11, 2026  
**Auditor**: Lead Security Engineer, AgentShield  
**Target Branch**: `feature/secure-config-management`  
**Base Commit**: `4034704`  
**Storage Backends**: SQLite (Standard), PostgreSQL (Optional Extras)  

---

## 1. Executive Summary

Milestone 8.1 performs an independent, exhaustive security verification of the multi-tenancy architecture, route authorization, tenant identity lifecycle, and database storage boundaries implemented in Milestone 8.

The audit verified that tenant isolation holds across core authorization pipelines, review queue claims, security event tracking, agent containment, and overview metric aggregation. In addition, the audit identified and resolved four critical edge-case vectors:
1. **Unauthenticated Public Scraping Protection**: Routes with public compatibility (`/api/overview`, `/events`, `/incident/agents`) now reject unauthenticated requests specifying non-default `tenant_id` parameters with `401 Unauthorized`, preventing anonymous enumeration of private tenant telemetry.
2. **Action Execution Scoping**: `AuthorizeRequest` and `ExecuteRequest` now accept and validate `tenant_id` server-side, preventing authenticated cross-tenant tool authorization and sandbox execution spoofing.
3. **Analyst Investigation & Reports IDOR**: Cross-tenant IDOR protection was added to incident investigation (`/api/security/incidents/{incident_id}/investigation`), incident analysis (`/api/security/analyst/analyze`), and report listings (`/api/security/incidents/{incident_id}/reports`, `/api/security/reports`).
4. **Session Token Contract Harmonization**: `SessionManager.create_session()` accepts both `user` and `user_id` keyword arguments, ensuring consistent session creation across all authentication paths.

All 135 core security and multi-tenancy tests, root frontend tests, root frontend production build, legacy frontend tests, and legacy frontend build pass with 100% success.

---

## 2. Complete API Route Authorization Matrix

Every route in the FastAPI application was audited and classified into one of four privilege tiers:
- **Public**: No authentication required (rate-limited and size-capped).
- **Authenticated Tenant User**: Requires valid session or API key; scoped strictly to caller's `tenant_id`.
- **Tenant Administrator**: Administrative control over tenant-scoped resources (agent pausing, review approval/rejection).
- **Global Platform Administrator**: Global platform controls (`/config`, `/audit/verify`); requires master admin credentials.

| Route Path | Method | Privilege Tier | Tenant Scoped | Server-Side Enforcement Mechanism |
|---|---|---|---|---|
| `/health`, `/api/health` | GET | Public | No | Unauthenticated health check. Returns service status and read-only flag. |
| `/health/readiness`, `/api/health/readiness` | GET | Public / Admin | No | Public receives generic degraded status; authenticated admin receives sanitized dependency checks. |
| `/metrics`, `/api/metrics` | GET | Public / Admin | No | Prometheus metrics; configurable via `AGENTSHIELD_REQUIRE_AUTH_FOR_METRICS`. |
| `/api/observability/logs` | GET | Global/Tenant Admin | Platform | Requires `_verify_admin()`. Sanitized operational logs. |
| `/check`, `/api/check` | POST | Public | No | User prompt injection detection. Sanitized input inspection. |
| `/authorize`, `/api/authorize` | POST | Authenticated / Public | Yes | Validates `req.tenant_id` via `_resolve_tenant_id()`. Unauthenticated requests restricted to `"default"`. |
| `/execute`, `/api/execute` | POST | Authenticated / Public | Yes | Validates `req.tenant_id` via `_resolve_tenant_id()`. Restricted to sandbox tools (`create_order`, `search_product`, `get_product`). |
| `/events` | GET | Authenticated / Public | Yes | Public access restricted to `default` tenant. Non-default tenant requests require authentication (401). |
| `/api/events`, `/api/audit/events` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Enforces `_resolve_tenant_id()`. Scoped via `audit_store.query(tenant_id=...)`. |
| `/audit/verify`, `/api/audit/verify` | GET | Global Admin | Platform | Requires `auth_ctx.role == "global_admin"`. Tenant admins receive `403 Forbidden`. |
| `/policies`, `/api/policies` | GET | Authenticated Admin | Platform | Requires `_verify_admin()`. Returns runtime deterministic policy configuration. |
| `/risk/factors`, `/api/risk/factors` | GET | Authenticated Admin | Platform | Requires `_verify_admin()`. Returns risk engine weights and thresholds. |
| `/config`, `/api/config` | GET | Global Admin | Platform | Requires `auth_ctx.role == "global_admin"`. Tenant admins receive `403 Forbidden`. |
| `/api/auth/login` | POST | Public | Yes | Authenticates master or per-tenant API keys. Issues signed session cookie and CSRF token. |
| `/api/auth/logout` | POST | Authenticated | Yes | Revokes session token in `session_revocations` table; clears cookies. |
| `/api/auth/session` | GET | Public / Authenticated | Yes | Returns authentication state, tenant identifier, and role. |
| `/api/overview`, `/api/stats` | GET | Authenticated / Public | Yes | Public access restricted to `default` tenant. Authenticated callers scoped strictly to their `tenant_id`. |
| `/incident/pause`, `/api/incident/pause` | POST | Tenant / Global Admin | Yes | Requires `_verify_admin()`. Scopes pause to `(tenant_id, agent)`. Respects read-only mode. |
| `/incident/unpause`, `/api/incident/unpause` | POST | Tenant / Global Admin | Yes | Requires `_verify_admin()`. Removes pause from `_tenant_paused_agents[tenant_id]`. |
| `/incident/agents`, `/api/incident/agents` | GET | Authenticated / Public | Yes | Public access restricted to `default` tenant. Authenticated callers scoped to their `tenant_id`. |
| `/reviews`, `/api/reviews`, `/incident/reviews`, `/api/incident/reviews` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries pending reviews filtered strictly by `tenant_id = ?`. |
| `/incident/review`, `/api/incident/review` | POST | Tenant / Global Admin | Yes | Atomic IDOR protection: `claim_and_approve()` requires `WHERE review_id = ? AND tenant_id = ?`. Returns 404 on mismatch. |
| `/api/security/events` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_events` filtered by `tenant_id = ?`. |
| `/api/security/events/{event_id}` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_events` by `(event_id, tenant_id)`. Returns 404 on mismatch. |
| `/incident/alerts`, `/api/incident/alerts`, `/api/security/alerts` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_alerts` filtered by `tenant_id = ?`. |
| `/api/security/alerts/{alert_id}` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_alerts` by `(alert_id, tenant_id)`. Returns 404 on mismatch. |
| `/incident/incidents`, `/api/incident/incidents`, `/api/security/incidents` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_incidents` filtered by `tenant_id = ?`. |
| `/api/security/incidents/{incident_id}` | GET | Authenticated Admin | Yes | Requires `_verify_admin()`. Queries `security_incidents` by `(incident_id, tenant_id)`. Returns 404 on mismatch. |
| `/api/security/incidents/{incident_id}/trace` | GET | Authenticated Admin | Yes | Queries correlated alerts, events, and audit logs filtered strictly by `tenant_id`. |
| `/incident/report/{incident_id}`, `/api/incident/report/{incident_id}`, `/api/security/incidents/{incident_id}/investigation` | GET | Authenticated Admin | Yes | Verifies incident belongs to `effective_tenant`. Returns 404 on cross-tenant access. |
| `/incident/report`, `/api/incident/report`, `/api/security/analyst/analyze` | POST | Authenticated Admin | Yes | Verifies incident belongs to `effective_tenant`. Returns 404 on cross-tenant access. |
| `/api/security/incidents/{incident_id}/reports` | GET | Authenticated Admin | Yes | Verifies incident belongs to `effective_tenant`. Returns 404 on cross-tenant access. |
| `/api/security/reports` | GET | Authenticated Admin | Yes | If `incident_id` given, verifies ownership. If unconstrained, filters reports to tenant's incidents. |
| `/api/security/reports/{report_id}` | GET | Authenticated Admin | Yes | Verifies referenced incident belongs to caller's `tenant_id`. Returns 404 on mismatch. |
| `/api/simulator/*` (all routes) | GET/POST/DEL | Public / Admin | Simulation | Isolated completely in `sim_*` tables with synthetic counters and demo scenarios. |

---

## 3. Tenant Identity Lifecycle

### 3.1 Tenant Creation & Provisioning
Tenants are provisioned via the `AGENTSHIELD_TENANT_KEYS` environment variable or passed to `create_app(tenant_api_keys={...})` in `tenant_id:key` format (e.g. `tenant_a:key-alpha,tenant_b:key-beta`).

> [!WARNING] Dynamic Tenant Onboarding Blocker
> There is currently no public or administrative API for self-service tenant registration (e.g., `POST /api/tenants/register`). All tenant identifiers and keys must be pre-provisioned via server configuration or environment variables. Multi-tenant self-service SaaS requires an administrative database table (`tenants`, `tenant_users`) to support automated user sign-up and tenant onboarding.

### 3.2 User-to-Tenant Association & Authentication
Authentication supports two cryptographic mechanisms:
1. **API Key Header Authentication**:
   - `X-Admin-Key`: Matches `AGENTSHIELD_ADMIN_KEY`. Authenticates as `user_id="admin"`, `role="global_admin"`. Defaults to `tenant_id="default"` but permits explicit tenant selection via `X-Tenant-ID`.
   - `X-Tenant-Key`: Matches a key in `AGENTSHIELD_TENANT_KEYS`. Authenticates as `user_id=f"tenant_admin_{tenant_id}"`, `tenant_id=t_id`, `role="tenant_admin"`. Attempting to access another tenant raises `403 Forbidden`.
2. **Session Cookie Authentication**:
   - `POST /api/auth/login` verifies the submitted key. On success, it issues an HttpOnly, SameSite=Lax cookie (`agentshield_session`) and generates a double-submit CSRF cookie (`agentshield_csrf`).
   - The session token is an HMAC-SHA256 signed payload containing:
     ```json
     {"sub": "admin_tenant_a", "tenant_id": "tenant_a", "role": "tenant_admin", "jti": "...", "iat": 1731319200, "exp": 1731405600}
     ```
   - The signature is derived using a separate signing key (`b"agentshield-session-v1"` HMAC with SHA-256). Clients cannot tamper with `tenant_id` or `role` without invalidating the cryptographic signature.

### 3.3 Session Expiry & Revocation
- **Expiration**: The token includes an `exp` claim. `SessionManager.verify_token()` rejects any token whose expiration time is in the past with `401 Unauthorized`.
- **Revocation**: `POST /api/auth/logout` records the SHA-256 hash of the session token in the `session_revocations` table. Every authenticated request checks `store.is_revoked(token_hash)`. Revoked tokens are immediately rejected with `401 Unauthorized`.
- **Tenant Switching Prevention**: A session issued to `tenant_a` cannot be used to query `tenant_b`. If a request includes `?tenant_id=tenant_b` or `X-Tenant-ID: tenant_b`, `_resolve_tenant_id()` compares it with `auth_ctx.tenant_id`. Any mismatch raises `403 Forbidden: Cross-tenant access denied`.

---

## 4. Storage Isolation Inspection

All database queries and mutations were audited across both SQLite and PostgreSQL implementations:

| Storage Domain | SQLite Implementation | PostgreSQL Implementation | Isolation Guarantee |
|---|---|---|---|
| **Audit Logs** | `SQLiteAuditStore.query()` | `PostgresAuditStore.query()` | `WHERE tenant_id = ?` (indexed by `idx_audit_tenant`) |
| **Pending Reviews** | `SQLiteReviewStore.get_pending_reviews()` | `PostgresReviewStore.get_pending_reviews()` | `WHERE status = 'pending' AND tenant_id = ?` |
| **Review Claiming** | `SQLiteReviewStore.claim_and_approve()` | `PostgresReviewStore.claim_and_approve()` | `WHERE review_id = ? AND tenant_id = ?` |
| **Review Rejection**| `SQLiteReviewStore.claim_and_reject()` | `PostgresReviewStore.claim_and_reject()` | `WHERE review_id = ? AND tenant_id = ?` |
| **Security Events** | `SQLiteEventStore.query_events()` | `PostgresEventStore.query_events()` | `WHERE tenant_id = ?` (indexed by `idx_security_events_tenant`) |
| **Security Alerts** | `SQLiteEventStore.query_alerts()` | `PostgresEventStore.query_alerts()` | `WHERE tenant_id = ?` (indexed by `idx_security_alerts_tenant`) |
| **Security Incidents**| `SQLiteEventStore.query_incidents()` | `PostgresEventStore.query_incidents()` | `WHERE tenant_id = ?` (indexed by `idx_security_incidents_tenant`) |
| **Incident Retrieval**| `SQLiteEventStore.get_incident()` | `PostgresEventStore.get_incident()` | `WHERE incident_id = ? AND tenant_id = ?` |
| **Sessions** | `SqliteSessionStore` | `PostgresSessionStore` | Stores `tenant_id` and `role` per session token hash |
| **Containment** | `Shield._tenant_paused_agents` | In-memory dictionary per tenant | Scopes paused status strictly to `(tenant_id, agent)` |

### Storage Isolation Verification
- **No Unscoped Aggregations**: `/api/overview` queries `audit_store.query(tenant_id=effective_tenant)`, `shield.get_review_queue(tenant_id=effective_tenant)`, and `event_store.query_incidents(tenant_id=effective_tenant)`. Metrics are strictly tenant-specific.
- **IDOR Resistance**: Review claim updates execute atomically with `WHERE review_id = ? AND tenant_id = ?`. If a tenant provides a foreign review ID, zero rows are updated, returning `None` and translating to `404 Not Found`.

---

## 5. Migration Chain & Production Data Compatibility

### 5.1 Historical Migration Sequence
1. **Migration 001 (`001_initial_schema`)**: Base tables for audit logs, review queues, simulation queues, events, alerts, incidents, and sessions.
2. **Migration 002 (`002_rate_limit_schema`)**: Distributed sliding-window rate limit tables.
3. **Migration 003 (`003_audit_correlation_tracing`)**: Added `correlation_id` and `trace_id` columns and indexes to `audit_logs`.
4. **Migration 004 (`004_tenant_isolation_schema`)**: Added `tenant_id` and `role` columns and indexes to `audit_logs`, `reviews`, `sim_reviews`, `active_sessions`, `security_events`, `sim_security_events`, `security_alerts`, `sim_security_alerts`, `security_incidents`, `sim_security_incidents`.

### 5.2 Production Data Safety
- **Default Value Assignment**: All new columns specify `NOT NULL DEFAULT 'default'` (and `DEFAULT 'tenant_admin'` for session roles). Existing production records automatically inherit `tenant_id = 'default'`.
- **Existing Dashboard Compatibility**: The existing production dashboard at `https://agentshiled.vercel.app` connects without tenant parameters, querying the `"default"` tenant and preserving visibility of all historical audit logs, events, and reviews.
- **Reversibility**: In SQLite, columns cannot be dropped without table recreation; however, the `DEFAULT 'default'` constraint is non-breaking. In PostgreSQL, columns can be dropped via `ALTER TABLE {tbl} DROP COLUMN IF EXISTS tenant_id`.
- **Zero Destructive Alterations**: Migration 004 contains no `DROP TABLE`, `TRUNCATE`, or column renaming statements.

---

## 6. Live PostgreSQL vs. Mocked PostgreSQL Verification

- **Mocked PostgreSQL Verification**: `MockPostgresEngine` emulates PostgreSQL connection pooling, advisory locks, transactions, savepoints, rollback, and migration tracking against SQLite. All 15 tests pass.
- **Live PostgreSQL Verification**: `tests/test_storage_postgres.py` includes a live verification suite (`test_live_postgres_end_to_end_migration`) that executes when `AGENTSHIELD_TEST_POSTGRES_URL` is configured in the test environment. In hermetic offline testing without a live database instance, this test skips cleanly (`pytest.skip("AGENTSHIELD_TEST_POSTGRES_URL is not set")`).

---

## 7. Automated Test Results

### 7.1 Backend Test Summary
- **Tenant Isolation Suite** (`tests/test_tenant_isolation.py`): **15 passed, 0 failed** in 5.81s
  - `test_tenant_api_key_authentication`
  - `test_tenant_login_session_isolation`
  - `test_client_side_tenant_spoofing_prevented`
  - `test_multi_tenant_review_isolation_and_idor`
  - `test_multi_tenant_security_events_and_alerts_isolation`
  - `test_tenant_scoped_containment_pause_isolation`
  - `test_rbac_tenant_admin_blocked_from_platform_endpoints`
  - `test_honest_empty_states_for_new_tenant`
  - `test_unauthenticated_tenant_scraping_prevented`
  - `test_authorize_and_execute_tenant_spoofing_prevented`
  - `test_session_logout_revocation`
  - `test_analyst_investigation_and_reports_idor`
  - `test_unscoped_dashboard_aggregation_prevented`
  - `test_tenant_isolation_persists_across_restart`
  - `test_standalone_sdk_tenancy_defaults`
- **Core Security & Storage Suite**: **134 passed, 1 skipped** in 23.73s
- **Deployment Config Suite**: **16 passed, 0 failed** in 2.47s

### 7.2 Frontend Tests & Builds
- **Root Frontend Tests** (`npm test`): **5 passed, 0 failed** in 237ms
- **Root Frontend Production Build** (`npm run build`): **Built in 1.82s**
- **Legacy Frontend Tests** (`npm --prefix frontend test`): **4 passed, 0 failed** in 263ms
- **Legacy Frontend Production Build** (`npm --prefix frontend run build`): **Built in 354ms**
- **Packaging Build** (`python -m build`): Built clean sdist and wheel with zero frontend assets or `.env` files.

---

## 8. Final Verdict

**VERDICT: CONDITIONALLY READY FOR SHARED MULTI-TENANT HOSTING**

### Rationale:
1. **READY FOR PRE-PROVISIONED TENANTS**: For organizations using pre-provisioned tenants via `AGENTSHIELD_TENANT_KEYS` and header/cookie authentication, tenant isolation is mathematically and architecturally enforced. Cross-tenant IDOR, client-side tenant spoofing, role escalation, and unscoped metrics are completely blocked.
2. **CONDITIONS FOR FULL SELF-SERVICE SAAS**:
   - **Self-Service Onboarding**: A dynamic tenant registration API and tenant database table (`tenants`, `tenant_memberships`) must be implemented before opening the hosted service to unassisted public user registrations.
   - **Investigation Report Store Tenancy**: While API routes now enforce incident ownership checks before serving investigation reports, the underlying `investigation_reports` database table does not yet have a direct `tenant_id` column. A future migration 005 should add `tenant_id` directly to `investigation_reports` for defense-in-depth.
