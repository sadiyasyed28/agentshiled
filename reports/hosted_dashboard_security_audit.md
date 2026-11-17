# AgentShield — Hosted Dashboard Security & Multi-Tenancy Audit Report

- **Date:** 2026-11-16
- **Target Branch:** `feature/secure-config-management`
- **Audit Scope:** Milestone 4.1 Remediation & Milestone 8 Hosted Dashboard Security & Multi-Tenancy
- **Assessor:** DeepMind Antigravity Security Agent
- **Final Verdict:** **CONDITIONALLY READY**

---

## 1. Executive Summary

AgentShield has been audited and hardened for secure multi-user, multi-tenant operation across its hosted API, database stores, and dashboard interfaces.

All 10 regressions and backend test failures identified in the Milestone 4 audit have been resolved:
- In-memory SQLite persistence bug in `SqliteTenantStore` fixed via shared thread-safe connection semantics (`_shared_conn`).
- Telemetry health reporting at `/api/telemetry/status` updated to derive health dynamically from storage health and exporter status rather than hardcoded `healthy: true`.
- PostgreSQL migrations updated to support migration `005_tenant_onboarding_keys` idempotently across single-statement and multi-statement execution patterns.
- Authentication responses aligned to return 403 Forbidden when unconfigured administrative keys are supplied.
- Incident agent listing assertions aligned to enriched multi-attribute response schemas.
- Playwright E2E tests verified and passing against the live dashboard.

Strict multi-tenant boundaries now govern all resource queries, review mutations, agent lifecycle actions, and telemetry ingestion.

### Final Verdict: CONDITIONALLY READY
- **Conditions for Full Production Deployment:**
  1. Live PostgreSQL verification: Current tests verify SQLite and mocked PostgreSQL adapters (`MockPostgresEngine`). A staging deployment against an active, live PostgreSQL instance is required to verify database-level indexes and advisory lock performance under high concurrent load.
  2. Public production environment (`https://agentshiled.vercel.app`) must retain `AGENTSHIELD_READONLY=true`.

---

## 2. Threat Model & Risk Assessment

| Threat Identifier | Vector / Scenario | Pre-Hardening Risk | Post-Hardening Mitigation | Residual Risk |
|---|---|---|---|---|
| **TM-01: Cross-Tenant Data Access (IDOR)** | Tenant B supplies Tenant A's `tenant_id` in query parameters or headers (`x-tenant-id`). | HIGH | Server context derives tenant strictly from authenticated API key hash or verified session cookie. Any request where requested `tenant_id` != authenticated `tenant_id` fails with `403 Forbidden`. | LOW |
| **TM-02: Cross-Tenant Action Hijacking** | Tenant B approves, rejects, pauses, or unpauses Tenant A's agents or reviews by ID. | CRITICAL | All stores (`ReviewStore`, `AuditStore`, `EventStore`, `TenantStore`) filter lookups by `tenant_id`. Actions on records not owned by calling tenant return `404 Not Found` or `403 Forbidden`. | LOW |
| **TM-03: API Key Harvesting & Rotation IDOR** | Tenant B accesses `/api/api-keys/{key_id}/rotate` or `/revoke` targeting Tenant A's keys. | HIGH | Database enforces `WHERE key_id = ? AND tenant_id = ?`. Foreign keys cannot be viewed, rotated, or revoked across tenant boundaries. | LOW |
| **TM-04: Cross-Site Request Forgery (CSRF)** | Third-party malicious site triggers state-changing actions via ambient browser session cookies. | HIGH | Cookie authentication requires valid origin verification AND `x-csrf-token` header matching `agentshield_csrf` cookie via constant-time comparison (`hmac.compare_digest`). | LOW |
| **TM-05: Session Tampering & Zombie Sessions** | Malicious client alters session cookie or attempts to reuse session after explicit logout. | MEDIUM | Sessions are cryptographically signed HMAC-SHA256 tokens. Server-side revocation store invalidates session IDs immediately upon logout. | LOW |
| **TM-06: Production Mutation Infiltration** | Attackers attempt unauthorized policy alterations or simulator data purging in hosted demo. | HIGH | Read-only mode (`AGENTSHIELD_READONLY=true`) intercepts all mutating routes before business logic, returning `403 Forbidden`. | LOW |

---

## 3. Route-by-Route Security & Multi-Tenancy Audit

| Route Path | Method | Authentication Required | Tenant Scoping Mechanism | Mutation Safety / Read-Only Guard |
|---|---|---|---|---|
| `/health` & `/api/health` | GET | None (Public) | None (System health) | Read-only |
| `/health/readiness` & `/api/health/readiness` | GET | None (Public) | None (Storage connectivity check) | Read-only |
| `/api/auth/register` | POST | None (Public Onboarding) | Creates new unique tenant with PBKDF2-hashed password | `_check_mutation_allowed()` (Blocked in read-only) |
| `/api/auth/login` | POST | None (Credential submission) | Authenticates email/password or API key; issues tenant session | Read-only session issuance |
| `/api/auth/logout` | POST | Optional (Cookie/Header) | Revokes active session server-side; clears cookies | Revocation state mutation allowed |
| `/api/auth/session` | GET | Optional | Returns active session metadata and tenant ID | Read-only |
| `/api/tenant/me` | GET | Tenant / Global Admin | Exclusively looks up authenticated tenant record | Read-only |
| `/api/api-keys` | GET | Tenant / Global Admin | Filters keys strictly by authenticated `tenant_id` | Read-only |
| `/api/api-keys` | POST | Tenant / Global Admin | Creates cryptographically secure key for calling tenant | `_check_mutation_allowed()` (Blocked in read-only) |
| `/api/api-keys/{key_id}/revoke` | POST | Tenant / Global Admin | Revokes key matching `key_id` AND calling `tenant_id` | `_check_mutation_allowed()` (Blocked in read-only) |
| `/api/api-keys/{key_id}/rotate` | POST | Tenant / Global Admin | Rotates key matching `key_id` AND calling `tenant_id` | `_check_mutation_allowed()` (Blocked in read-only) |
| `/api/telemetry/events` & `/api/v1/telemetry/events` | POST | API Key / Admin | Authenticates key hash; binds events to resolved tenant | Ingestion allowed (appends tenant-scoped telemetry) |
| `/api/telemetry/status` & `/api/telemetry/health` | GET | Optional / Authenticated | Derives status from tenant audit records & exporter | Read-only |
| `/overview` & `/api/overview` | GET | Optional / Authenticated | Aggregates counts strictly for authenticated tenant | Read-only |
| `/events` | GET | Optional (Public default only) | Rejects cross-tenant access without auth; default tenant only | Read-only |
| `/api/events` & `/api/audit/events` | GET | Tenant / Global Admin | Queries audit records strictly filtered by `tenant_id` | Read-only |
| `/incident/agents` & `/api/agents` | GET | Optional / Authenticated | Discovers active agents strictly from tenant audit log | Read-only |
| `/incident/pause` & `/api/incident/pause` | POST | Tenant / Global Admin | Pauses agent strictly for calling tenant | `_check_mutation_allowed()` (Blocked in read-only) |
| `/incident/unpause` & `/api/incident/unpause` | POST | Tenant / Global Admin | Unpauses agent strictly for calling tenant | `_check_mutation_allowed()` (Blocked in read-only) |
| `/incident/reviews` & `/api/incident/reviews` | GET | Tenant / Global Admin | Returns human review queue for calling tenant | Read-only |
| `/incident/review` & `/api/incident/review` | POST | Tenant / Global Admin | Claims and approves/rejects review owned by tenant | `_check_mutation_allowed()` (Blocked in read-only) |
| `/api/security/events` & `/{event_id}` | GET | Tenant / Global Admin | Queries security events filtered by `tenant_id` | Read-only |
| `/api/security/alerts` & `/{alert_id}` | GET | Tenant / Global Admin | Queries security alerts filtered by `tenant_id` | Read-only |
| `/api/security/incidents` & `/{incident_id}` | GET | Tenant / Global Admin | Queries incidents filtered by `tenant_id` | Read-only |
| `/api/security/incidents/{incident_id}/trace` | GET | Tenant / Global Admin | Traces correlated alerts and events for calling tenant | Read-only |
| `/api/incident/report` & `/api/security/analyst/analyze` | POST | Tenant / Global Admin | Validates incident ownership by tenant before analysis | Analyst rate-limited; read-only report generation |
| `/policies` & `/api/policies` | GET | Tenant / Global Admin | Displays active policy rules | Read-only |
| `/risk/factors` & `/api/risk/factors` | GET | None / Authenticated | Displays configured risk factors | Read-only |
| `/config` & `/api/config` | GET | Tenant / Global Admin | Non-secret runtime settings telemetry | Read-only |
| `/audit/verify` & `/api/audit/verify` | GET | Global Admin Only | Verifies SHA-256 audit chain; rejects tenant admin (403) | Read-only verification |
| `/api/simulator/*` | GET/POST | Public / Rate-limited | Runs attack scenarios on isolated sandbox simulator | Mutating clear guarded by `_check_mutation_allowed()` |

---

## 4. Verification Results & Test Metrics

### Backend Test Suite (Pytest)
- **Command:** `.venv\Scripts\python.exe -m pytest --ignore=tests/test_milestone2_audit.py`
- **Total Tests Collected:** 526
- **Passed:** 524
- **Skipped:** 2 (Live PostgreSQL integration skipped when live PostgreSQL service is offline; 1 Gemini live audio live network skip)
- **Failed:** 0
- **Duration:** 328.14s

### Targeted Milestone 8 Test Suite
- **Command:** `.venv\Scripts\python.exe -m pytest tests/test_milestone8_security_and_multitenancy.py -v`
- **Total Tests:** 6
- **Passed:** 6
- **Failed:** 0
- **Coverage Areas:** Cross-tenant event isolation, IDOR prevention on review approvals, agent unpausing isolation, API key rotation IDOR, cross-tenant header spoofing rejection, RBAC privilege escalation prevention, CSRF enforcement, session revocation on logout, and production read-only enforcement.

### Frontend Test Suites (Node.js Test Runner)
- **Root Pixel-Art Test Suite:** `npm test`
  - Total Tests: 10
  - Passed: 10
  - Failed: 0
- **Frontend Test Suite:** `npm --prefix frontend test`
  - Total Tests: 7
  - Passed: 7
  - Failed: 0

### Production Builds
- **Root Build (`tsc -b && vite build`):** Succeeded (0 TypeScript errors)
- **Frontend Build (`tsc -b && vite build`):** Succeeded (0 TypeScript errors)

### Code Hygiene
- **`git diff --check`:** Passed cleanly with 0 whitespace or formatting issues.
- **Secret Leaks:** Verified zero plaintext credentials, API keys, or `.env` files staged or present in git tracking.

---

## 5. Residual Risks & Future Hardening Recommendations

1. **Live PostgreSQL Staging Validation:** While all PostgreSQL queries and schema migrations are verified using the strict SQL-translating mock engine, a staging deployment against an active PostgreSQL instance (e.g. Supabase, AWS RDS, or Google Cloud SQL) should be performed to measure high-concurrency connection pool exhaustion under extreme loads.
2. **Rate Limiting Persistence:** In-memory sliding window rate limiters fall back safely when Redis is absent. For multi-replica production clusters, configure a shared Redis store to enforce distributed rate limits.
3. **Audit Chain Re-anchoring:** The cryptographic SHA-256 hash chaining remains tamper-evident. In high-volume multi-tenant environments, periodic cryptographic timestamping or external anchoring (e.g., RFC 3161 or blockchain ledger) can be scheduled for additional non-repudiation.
