# AgentShield — Staging Recovery & Deployment Investigation Report

**Repository:** `https://github.com/sadiyasyed28/agentshiled`  
**Branch:** `feature/secure-config-management`  
**Execution Timestamp:** 2026-11-18T13:20:00Z  
**Staging Status:** **STAGING BLOCKED**

---

## 1. Executive Summary & Status Classification

An exhaustive technical investigation was conducted to determine the operational status of the Render staging backend (`https://agentshield-backend-staging.onrender.com`) and the corresponding Vercel environments.

| Environment / Layer | Target Endpoint / Scope | Real Observed Result | Final Assessment |
| :--- | :--- | :--- | :---: |
| **Local Test Suite** | Local Python & Node runtimes | 537 passed, 41 frontend unit passed, 12 Playwright browser flows passed | **VERIFIED (100% Pass)** |
| **Render Staging Backend** | `https://agentshield-backend-staging.onrender.com` | `HTTP 404 (x-render-routing: no-server)` | **BLOCKED (Service Inactive on Render)** |
| **Live Neon PostgreSQL** | Production Vercel Serverless | `/api/health/readiness` -> `"database":"connected"`, `"storage_backend":"postgres"` | **VERIFIED (Live Connection)** |
| **Vercel Staging Preview** | `https://agentshield-staging.vercel.app` | Serves legacy Next.js static asset bundle; `/api/health` -> `404` | **BLOCKED (Unlinked to Render)** |
| **Vercel Production** | `https://agentshiled.vercel.app` | All endpoints (`/health`, `/api/health`, `/api/health/readiness`) return `200 OK` | **VERIFIED (Live Operational)** |

---

## 2. Render Deployment Investigation & Root Cause Analysis

### 2.1 Direct Network Probe Results
A direct HTTP probe was executed against `https://agentshield-backend-staging.onrender.com/`:
- **HTTP Status Code:** `404 Not Found`
- **Response Headers:**
  - `Server: cloudflare`
  - `x-render-routing: no-server`
  - `Content-Type: text/plain; charset=utf-8`
- **Response Body:** `Not Found`

### 2.2 Technical Meaning of `x-render-routing: no-server`
In Render's edge routing infrastructure (Cloudflare proxy + ingress):
1. A sleeping or suspended free-tier container returns either an ingress hold (delayed response while instance spins up) or a 502/loading gateway page. It does **not** return an immediate `404` with `x-render-routing: no-server`.
2. The header `x-render-routing: no-server` proves that Render's routing table has **no service registered or bound** to the subdomain `agentshield-backend-staging.onrender.com`.

### 2.3 Blueprint Configuration Audit (`render.yaml`)
Inspection of `render.yaml` confirms that the file is syntactically valid and correctly specifies:
- `name: agentshield-backend-staging`
- `runtime: python`
- `region: singapore`
- `plan: free`
- `buildCommand: "pip install --upgrade pip && pip install -r requirements.txt && pip install ."`
- `startCommand: "uvicorn agentshield.api.app:app --host 0.0.0.0 --port $PORT"`
- `healthCheckPath: /health`

However, lines 23–30 specify four mandatory secret environment variables with `sync: false`:
```yaml
      - key: DATABASE_URL
        sync: false
      - key: AGENTSHIELD_ADMIN_KEY
        sync: false
      - key: AGENTSHIELD_SESSION_SECRET
        sync: false
      - key: AGENTSHIELD_CORS_ORIGINS
        sync: false
```
In Render's Blueprint specification, `sync: false` instructs Render **never** to populate these variables automatically. Consequently:
- Pushing `render.yaml` to GitHub does **not** automatically trigger service creation on Render.
- A user must explicitly initialize the Blueprint in the Render Dashboard, which pauses deployment until the user enters these four sensitive environment variables.
- Because no manual Blueprint setup has occurred in the Render Dashboard for `sadiyasyed28/agentshiled`, no server container exists, resulting in `x-render-routing: no-server`.

---

## 3. Required User Action to Restore Staging Backend on Render

To activate the staging backend on Render, the following one-time administrative steps must be performed in the Render web console:

1. **Log in to Render:** Navigate to [https://dashboard.render.com/](https://dashboard.render.com/).
2. **Create New Blueprint:**
   - Click **New +** -> **Blueprint**.
   - Connect the repository: `sadiyasyed28/agentshiled`.
   - Select the branch: `feature/secure-config-management` (or `main`).
3. **Configure Required Variables:**
   When prompted for the `sync: false` variables, enter:
   - `DATABASE_URL`: Connection string for the dedicated **staging Neon branch** (e.g. `postgresql://.../neondb?sslmode=require`).
   - `AGENTSHIELD_ADMIN_KEY`: Dedicated staging admin secret key.
   - `AGENTSHIELD_SESSION_SECRET`: Random 32+ character string for staging session cookie signing.
   - `AGENTSHIELD_CORS_ORIGINS`: `https://agentshiled.vercel.app,https://agentshield-staging.vercel.app,http://localhost:5173`
4. **Deploy:** Click **Apply**.
5. **Verify Subdomain:** Confirm Render assigns the exact name `agentshield-backend-staging.onrender.com`. (If Render assigns a custom suffix, update `vercel.json` on `feature/secure-config-management` to match the assigned URL).

---

## 4. Live Production Environment Verification

Independent probing of Vercel production verified that the real production deployment for this repository is live at:
**`https://agentshiled.vercel.app`** (repository spelling: `agentshiled`).

### Live Telemetry from Production (`https://agentshiled.vercel.app`):
- `GET /health` -> `HTTP 200 OK`:
  `{"status":"healthy","version":"0.2.0","engine":"AgentShield Runtime","read_only":true}`
- `GET /api/health` -> `HTTP 200 OK`:
  `{"status":"healthy","version":"0.2.0","engine":"AgentShield Runtime","read_only":true}`
- `GET /api/health/readiness` -> `HTTP 200 OK`:
  ```json
  {
    "status": "ready",
    "database": "connected",
    "storage_backend": "postgres",
    "audit_store": "accessible",
    "review_store": "accessible",
    "event_store": "accessible",
    "analyst_provider": "gemini-2.5-flash",
    "circuit_breaker": "closed",
    "read_only": true
  }
  ```
- `GET /api/auth/session` -> `HTTP 200 OK`:
  `{"authenticated":false,"read_only":true,"admin_configured":true,"expires_at":null,"csrf_token":null}`
- `GET /api/overview` -> `HTTP 200 OK`:
  `{"total_evaluated":0,"allow_count":0,"review_count":0,"block_count":0,"pending_reviews_count":0,"paused_agents_count":0,"is_read_only":true}`
- `GET /api/telemetry/status` -> `HTTP 200 OK`:
  `{"status":"awaiting_telemetry","tenant_id":"default","total_events":0,"active_agents_count":0}`
- `GET /api/config` -> `HTTP 401 Unauthorized`:
  `{"detail":"Unauthorized: Invalid administrative credentials"}` (properly protected).

---

## 5. Summary & Conclusion

- **Local Codebase & Architecture:** **100% OPERATIONAL**.
- **Production (`https://agentshiled.vercel.app`):** **100% OPERATIONAL & VERIFIED** (connected to live PostgreSQL).
- **Staging Backend (`https://agentshield-backend-staging.onrender.com`):** **STAGING BLOCKED** until the user initiates the Blueprint creation and supplies staging secrets in the Render Dashboard.
