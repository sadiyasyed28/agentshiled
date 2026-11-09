# AgentShield

> **Deterministic Runtime Security SDK for Tool-Using AI Agents**
>
> Propose → Validate → Risk → Policy → Decision → Execute → Audit

AgentShield is an open-source, framework-independent Python runtime security SDK and enforcement layer for tool-using AI agents. When an AI agent proposes an action, AgentShield authenticates the agent, validates argument schemas, computes deterministic risk scores, and applies code-defined deterministic security policies (`ALLOW` / `REVIEW` / `BLOCK`). Only permitted actions are executed; every evaluation and execution is recorded to a cryptographically chained audit ledger.

```
+--------------------+        +-----------------------+        +---------------+
|     AI Agent       | -----> |      AgentShield      | -----> | External Tool |
| (Proposes Action)  |        | (Runtime Interceptor) |        | / API Action  |
+--------------------+        +-----------------------+        +---------------+
                                      |       |
                         [Evaluate Policy]   [Human Review]
                                      |       |
                                  [Blocked / Allowed]
```

---

## Features & Screens

AgentShield includes a retro 16-bit pixel-art security dashboard providing full runtime visibility and control:

- **Overview Dashboard**: Agent runtime metrics, active risk score indicators, real-time security activity stream, attention queue, and quick actions.
- **Events Screen**: Complete audit trail of every intercepted agent action with real-time search, multi-attribute filters, and slide-over event payload inspection drawer.
- **Human-in-the-Loop Review**: Dedicated review queue for high-risk actions requiring administrative approval, complete with argument inspection, policy checks, denial reasons, and batch approval.
- **Policies & Agents**: Centralized security policy management (allowed tools, rate limits, domain restrictions, behavior rules) alongside a full agent runtime registry.
- **Security Benchmarks**: Evaluates protection effectiveness against OWASP Agentic vectors (prompt injection, tool misuse, privilege escalation, SSRF, volume limits), comparing baseline execution against AgentShield protected mode.
- **Settings & Telemetry**: Safe inspection of non-secret runtime limits, environment configuration, and active policy hashes with zero secret leakage.

---

## Non-Negotiable Security Principles

1. **Deterministic Authority**: LLMs and RAG are never the final security authority. Deterministic policy fails closed.
2. **Fail-Closed Default**: Unknown tool, unknown agent, malformed request, or policy denial strictly evaluates to `BLOCK`.
3. **Execution Invariant**: `BLOCK` never invokes the tool callable. `ALLOW` invokes the tool exactly once per `execute()`.
4. **Unidirectional Escalation**: Risk score can escalate a decision to `REVIEW` or `BLOCK`, but can never turn a denial into `ALLOW`.
5. **Frozen Argument Validation**: Validates normalized arguments and executes those exact frozen values.
6. **Destination Allowlisting**: External destinations are allowlisted by parsed hostname, never substring.
7. **Credential Isolation**: Only the executor holds tool credentials; AI agents never hold or invoke tools directly.
8. **Cryptographic Ledger**: Cryptographically chained audit records verify ledger integrity and detect tampering.

---

## Supported Platforms, Frameworks & Installation

### Supported Python Versions
- **Python 3.11, 3.12, 3.13**: Officially supported across all adapters and optional extras.
- **Python 3.14**: Supported for standalone core SDK, declarative policy, decorator tool protection, and LangChain integration. (CrewAI is constrained to Python < 3.14 due to upstream binary wheel availability).

### Supported Framework Versions
- **LangChain**: `langchain-core>=0.2.0` (supports LangChain 0.2+)
- **CrewAI**: `crewai>=0.28.0` (Python 3.11–3.13)

### Installation Matrix

AgentShield enforces a minimal core installation (`pydantic>=2.0` only). All integrations, servers, and cloud providers are isolated behind optional extras:

```bash
# Standalone Core SDK (Minimal dependencies: pydantic only)
pip install agentshield

# Declarative YAML Policy Configuration
pip install "agentshield[yaml]"

# LangChain Integration
pip install "agentshield[langchain]"

# CrewAI Integration
pip install "agentshield[crewai]"

# FastAPI Server & Dashboard Backend
pip install "agentshield[server]"

# Production PostgreSQL Storage Backend
pip install "agentshield[postgres]"

# Gemini AI Security Analyst Provider
pip install "agentshield[gemini]"

# Complete Production & Developer Bundle
pip install "agentshield[all]"
```

---

## Storage & Database Architecture

AgentShield provides pluggable, ACID-compliant persistent storage for audit logs, human review queues, security events, analyst reports, and simulation telemetry:

### 1. SQLite Storage (Default)
- **Use Case**: Local development, standalone CLI agents, unit testing, and single-instance applications.
- **Concurrency & Integrity**: Uses `PRAGMA journal_mode=WAL;` and `BEGIN IMMEDIATE` transactions to prevent dirty reads and ensure atomic, race-free review claims.
- **Ledger Security**: Implements SHA-256 cryptographic hash-chaining linked to a genesis hash to verify tamper-evidence across restarts.
- **Configuration**: Automatic zero-config fallback to local files or `:memory:`.

### 2. PostgreSQL Storage (Production & Serverless)
- **Use Case**: Multi-instance deployments, high-throughput cloud workloads, and Vercel serverless functions.
- **Concurrency & Locking**: Employs row-level `SELECT ... FOR UPDATE` locking to guarantee atomic at-most-once tool execution across distributed workers.
- **Schema Management**: Includes automated, advisory-locked schema migrations (`MigrationManager`).
- **Configuration**: Set `AGENTSHIELD_DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require` (or `DATABASE_URL`). Fails closed with diagnostic `ConfigurationError` if connection or driver is missing.

---

## Security Guarantees & Operational Boundaries

| Guarantee | Boundary / Requirement |
| :--- | :--- |
| **Deterministic Authority** | Policy rules strictly evaluate to `BLOCK` or `ALLOW`. Risk scores can escalate `ALLOW` to `REVIEW` or `BLOCK`, but can never override a policy denial. |
| **Atomic At-Most-Once Execution** | Competing supervisor approvals for the same review resolve atomically; exactly one worker executes the tool callable. Repeated or replayed approvals fail closed. |
| **Incident Containment** | Paused agents cannot execute tools under any circumstance—including via supervisor review approval. Approvals for paused agents immediately fail closed. |
| **Secret Redaction** | Sensitive credentials (passwords, bearer tokens, API keys, private keys) are automatically sanitized across audit stores, review arguments, and event logs. |
| **Operational Boundaries** | Framework callbacks (e.g. LangChain `on_tool_start` or CrewAI agent loggers) run outside AgentShield's execution boundary; callers must ensure sensitive variables are not printed by external hooks. |

---

## Tech Stack & Architecture

- **Core SDK**: Python 3.12+ / 3.13 / 3.14 (`src/` layout, dataclasses, frozen models)
- **Deterministic Policy Engine**: Code-declared `PolicyConfiguration` with immutable `version_hash`
- **Deterministic Risk Engine**: 0–100 heuristic and rule-based scoring with 8 core risk factors
- **Storage Layer**: Pluggable storage abstraction supporting SQLite (default local) and PostgreSQL (production serverless)
- **API Backend**: FastAPI with strict CORS origin verification, HMAC-SHA256 sessions, and rate limiting
- **Frontend Dashboard**: React 19, TypeScript, Vite, Tailwind CSS, pixel-art retro theme (`frontend/`)

---

## Getting Started: Local Installation

### 1. Clone the Repository & Set Up Virtual Environment

```bash
git clone https://github.com/sadiyasyed28/agentshiled.git
cd agentshiled

# Create and activate Python virtual environment
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
pip install -e .
```

### 3. Install Frontend Dependencies

```bash
cd frontend
npm install
cd ..
```

---

## Configuration Workflow

AgentShield strictly separates runtime code from secrets and operational parameters. All configuration is managed via environment variables.

### Step 1: Create Your Local `.env` File

Copy the provided template:

```bash
cp .env.example .env
```

> **Security Rule**: The `.env` file is excluded from Git via `.gitignore`. Never commit or push `.env` files with real credentials or API keys.

---

### Step 2: Configure Environment Variables

Open `.env` in your text editor and set the values described below:

#### 1. Administrative Authentication & Sessions
| Variable | Description | Where to Enter / How to Obtain |
| :--- | :--- | :--- |
| `AGENTSHIELD_ADMIN_KEY` | Master administrative secret for API endpoints (`X-Admin-Key`) and UI login. | Generate a strong 32+ char key: `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `AGENTSHIELD_SESSION_SECRET` | Signing key for HMAC-SHA256 session cookies. | Generate a random 32+ char key (or leave empty to derive from admin key). |

#### 2. Network & Operational Mode
| Variable | Description | Where to Enter / How to Obtain |
| :--- | :--- | :--- |
| `AGENTSHIELD_ENV` | Environment identifier (`development`, `staging`, `production`). | Set to `development` locally; `production` on deployment. |
| `AGENTSHIELD_READONLY` | Read-only demo mode (`true` or `false`). | Set to `false` for interactive development; `true` for public demonstrations. |
| `AGENTSHIELD_CORS_ORIGINS` | Permitted browser origins (comma-separated, no wildcards). | Set to `http://localhost:5173,http://127.0.0.1:5173` for local Vite dev. |

#### 3. Storage & Database Settings
| Variable | Description | Where to Enter / How to Obtain |
| :--- | :--- | :--- |
| `AGENTSHIELD_STORAGE_BACKEND` | Active storage backend: `sqlite` or `postgres`. | Keep `sqlite` for zero-setup local dev. |
| `AGENTSHIELD_DATABASE_URL` | PostgreSQL connection string with SSL mode. | Optional locally; required if testing with PostgreSQL. |
| `AGENTSHIELD_AUDIT_DB` | SQLite audit file path (default: `agentshield_audit.db`). | Optional; customize if storing DB in a specific folder. |

#### 4. LLM Security Analyst (Optional)
| Variable | Description | Where to Enter / How to Obtain |
| :--- | :--- | :--- |
| `AGENTSHIELD_ANALYST_PROVIDER` | Security Analyst provider: `mock` or `gemini`. | Default is `mock` (no API key needed). Set to `gemini` for live Gemini analysis. |
| `GEMINI_API_KEY` | Google Gemini API key. | Obtain from [Google AI Studio](https://aistudio.google.com/). |
| `AGENTSHIELD_ALLOW_MOCK_FALLBACK` | Fails over to mock analyst if Gemini is down (`true`/`false`). | Keep `true` to ensure zero disruption on transient Gemini API timeouts. |

#### 5. Reliability & Rate Limits
| Variable | Description | Where to Enter / How to Obtain |
| :--- | :--- | :--- |
| `AGENTSHIELD_RATE_LIMIT_AGENT` | Request quota per agent (e.g. `100/minute`). | Customize based on expected agent throughput. |
| `AGENTSHIELD_RATE_LIMIT_TOOL` | Request quota per agent + tool (e.g. `60/minute`). | Prevents runaway agent loops against specific tools. |
| `AGENTSHIELD_MAX_TOOL_EXECUTION_SECONDS` | Maximum runtime in seconds before timing out tool execution. | Default `30.0` seconds. |
| `AGENTSHIELD_MAX_TOOL_CALLS_PER_SESSION` | Cumulative tool invocations permitted per correlation ID. | Default `50` calls. |

---

### Step 3: Validate Your Configuration

AgentShield includes a built-in configuration validator that checks your environment and ensures no secrets are printed or leaked:

```bash
python -m agentshield.config_validation
```

Output preview:
```
============================================================
AgentShield Runtime Configuration Audit Report
============================================================
Overall Status: [OK] VALID

Sanitized Configuration Summary:
  environment              : development
  read_only_mode           : false
  admin_auth               : configured
  storage_backend          : sqlite
  analyst_provider         : mock
  mock_fallback_allowed    : true
============================================================
```

---

## Running the Application Locally

### Start Backend API Server

```bash
python -m uvicorn agentshield.api.app:app --host 127.0.0.1 --port 8000 --reload
```
API documentation is available at `http://127.0.0.1:8000/docs`.

### Start Frontend Dashboard

```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## Standalone Python SDK & Declarative Policy

AgentShield can be used as a standalone Python SDK independently of any web server or dashboard:

```bash
# Core lightweight installation (pydantic only):
pip install agentshield

# With YAML policy loading support:
pip install "agentshield[yaml]"
```

### 1. Declarative Policy via Dictionary

```python
from agentshield import Shield, PolicyConfiguration

# Define policy declaratively
policy = PolicyConfiguration.from_dict({
    "agents": {
        "support_bot": {
            "allowed_tools": ["lookup_order", "check_status"],
            "denied_tools": ["process_refund"],
            "allowed_destinations": ["api.store.internal"],
        }
    },
    "tools": {
        "lookup_order": {
            "max_quantity": "inf",
            "allowed_destinations": ["api.store.internal"],
            "argument_schema": {
                "order_id": "str",
            },
        },
        "process_refund": {
            "max_amount": 500.0,
            "required_permissions": ["finance:refund"],
        },
    },
})

shield = Shield(policy=policy)

# Register tool implementation (held exclusively by the executor)
shield.registry.register("lookup_order", lambda args: {"status": "shipped"})

# Authorize and execute safely
result = shield.execute(
    agent="support_bot",
    tool="lookup_order",
    arguments={"order_id": "ord_123", "destination": "api.store.internal"},
)
print(result.decision.decision.value)  # ALLOW
print(result.tool_result)             # {'status': 'shipped'}
```

### 2. Declarative Policy via YAML

```python
from agentshield import Shield, PolicyConfiguration

# Load policy directly from a YAML file or string (requires agentshield[yaml])
policy = PolicyConfiguration.from_yaml("policy.yaml")
shield = Shield(policy=policy)
```

Example `policy.yaml`:

```yaml
version: "1"
agents:
  support_bot:
    allowed_tools:
      - lookup_order
      - check_status
    denied_tools:
      - process_refund
    allowed_destinations:
      - api.store.internal
tools:
  lookup_order:
    max_quantity: inf
    allowed_destinations:
      - api.store.internal
    argument_schema:
      order_id: str
```

### 3. Decorator-Based Tool Protection (`@shield.protect_tool`)

Protect existing Python functions and methods effortlessly with `@shield.protect_tool`:

```python
from agentshield import Shield, PolicyConfiguration, ToolBlockedError, ToolReviewRequiredError

shield = Shield(policy=policy)

# Protect synchronous or asynchronous functions
@shield.protect_tool(agent="support_bot")
def lookup_order(order_id: str) -> dict:
    return {"order_id": order_id, "status": "shipped"}

@shield.protect_tool(agent="support_bot", permissions=["finance:refund"])
def process_refund(order_id: str, amount: float) -> dict:
    return {"refund_id": "ref_123", "amount": amount}

# 1. ALLOW: Invokes the function exactly once
result = lookup_order("ord_9901")

# 2. BLOCK: Never invokes the function, raises ToolBlockedError
try:
    process_refund("ord_9901", amount=150.0)  # Missing permission or denied
except ToolBlockedError as err:
    print(f"Blocked: {err}")

# 3. REVIEW: High-risk actions are enqueued and raise ToolReviewRequiredError
try:
    process_refund("ord_9901", amount=5000.0)
except ToolReviewRequiredError as err:
    print(f"Human review required: {err.review_id}")
    # Approved by human supervisor:
    shield.approve_review(err.review_id, approver="supervisor_1")
```

### 4. LangChain Integration (`agentshield[langchain]`)

AgentShield provides an adapter for LangChain tools (`BaseTool`, `@tool`, `StructuredTool`).

#### Installation
```bash
pip install agentshield[langchain]
```
Supported LangChain versions: `langchain-core>=0.2.0` (compatible with LangChain 0.2.x, 0.3.x, and 1.x).
The core `agentshield` package does not depend on LangChain; all integration imports are lazy.

#### Usage
```python
from langchain_core.tools import tool
from agentshield import Shield, PolicyConfiguration, ToolBlockedError, ToolReviewRequiredError

# Initialize Shield with policy
shield = Shield(policy=policy)

@tool
def process_refund(order_id: str, amount: float) -> dict:
    """Process customer refund."""
    return {"order_id": order_id, "amount": amount, "status": "refunded"}

# Wrap existing LangChain tool
safe_refund = shield.protect_langchain_tool(
    process_refund,
    agent="support_bot",
    permissions=["finance:refund"],
)

# Preserves tool name, description, args_schema, and args:
print(safe_refund.name)         # 'process_refund'
print(safe_refund.description)  # 'Process customer refund.'
print(safe_refund.args_schema)  # Pydantic schema

# 1. ALLOW: Invokes the underlying tool exactly once
result = safe_refund.invoke({"order_id": "ord_101", "amount": 25.0})

# 2. BLOCK: Policy violations fail closed without invoking underlying tool
try:
    safe_refund.invoke({"order_id": "ord_101", "amount": 9000.0})
except ToolBlockedError as err:
    print(f"Blocked: {err}")

# 3. REVIEW & Approval Workflow:
try:
    safe_refund.invoke({"order_id": "ord_101", "amount": 2500.0})
except ToolReviewRequiredError as err:
    print(f"Enqueued for review: {err.review_id}")
    # The tool was NOT executed. A supervisor approves the review:
    res = shield.approve_review(err.review_id, approver="lead_auditor")
    print(res.tool_result)  # Executes tool once with validated frozen arguments

# 4. Async tools:
# Supported natively via await safe_tool.ainvoke({...})
```

#### Review Approval Resume Semantics
When an action is flagged for `REVIEW`, the request arguments are normalized, validated, and frozen into the persistent `ReviewStore`.
Upon approval via `shield.approve_review(review_id, approver=...)`, AgentShield retrieves the frozen arguments from the store and executes the underlying tool via its registered callable exactly once. Subsequent approval attempts fail closed (at-most-once initiation). For async-only tools approved in synchronous review contexts, AgentShield executes via safe event loop delegation.

### 5. CrewAI Integration (`agentshield[crewai]`)

AgentShield provides a security adapter for CrewAI tools (`crewai.tools.BaseTool` subclasses and custom callables).

#### Installation
```bash
pip install "agentshield[crewai]"
```
Supported CrewAI versions: `crewai>=0.28.0` (for Python < 3.14). The core `agentshield` package does not depend on CrewAI; all integration imports are lazy.

#### Usage
```python
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from agentshield import Shield, PolicyConfiguration, ToolBlockedError, ToolReviewRequiredError

shield = Shield(policy=policy)

class WireTransferInput(BaseModel):
    to_account: str = Field(description="Recipient account")
    amount: float = Field(description="Wire amount")

class WireTransferTool(BaseTool):
    name: str = "wire_transfer"
    description: str = "Execute an institutional wire transfer."
    args_schema: type[BaseModel] = WireTransferInput

    def _run(self, to_account: str, amount: float) -> dict:
        return {"to_account": to_account, "amount": amount, "status": "sent"}

# Wrap CrewAI tool with AgentShield runtime protection
safe_wire = shield.protect_crewai_tool(
    WireTransferTool(),
    agent="financial_agent",
    permissions=["treasury:wire"],
)

# Preserves tool metadata and CrewAI BaseTool interface:
print(safe_wire.name)             # 'wire_transfer'
print(safe_wire.description)      # 'Execute an institutional wire transfer.'
print(safe_wire.args_schema)      # WireTransferInput
print(safe_wire.result_as_answer) # False

# 1. ALLOW: Invokes the underlying tool exactly once
result = safe_wire.run(to_account="ACC-01", amount=500.0)

# 2. BLOCK: Violations fail closed without invoking underlying tool
try:
    safe_wire.run(to_account="ACC-01", amount=25000.0)  # Exceeds max_amount
except ToolBlockedError as err:
    print(f"Blocked: {err}")

# 3. REVIEW & Approval Workflow:
try:
    safe_wire.run(to_account="ACC-01", amount=5000.0)   # High risk
except ToolReviewRequiredError as err:
    print(f"Enqueued for review: {err.review_id}")
    # Tool was NOT executed prior to approval.
    approval = shield.approve_review(err.review_id, approver="security_officer")
    print(approval.tool_result)  # Executes tool once with validated frozen arguments

# 4. Async Execution:
# Supported natively via await safe_wire.arun(...) / _arun(...)
```

#### CrewAI Invariants & Security Guarantees
- **ALLOW**: Underlying tool `run()`, `_run()`, `arun()`, or `_arun()` executes exactly once per authorized invocation.
- **BLOCK**: Policy violations, unknown tools, unauthorized agents, or destination mismatches fail closed immediately with zero tool invocations.
- **REVIEW**: Elevated risk triggers human approval queue. The underlying tool never executes prior to approval.
- **Frozen Arguments & At-Most-Once Approval**: Arguments are validated and frozen at proposal time; approvals execute using those exact frozen values. Repeated approvals fail closed.
- **Exception Safety**: Internal errors within underlying tools are audited with status `error` or `timeout` and re-raised without retry loops bypassing security checks.

---

## Vercel Deployment Guide

AgentShield is configured for deployment on Vercel with a Python serverless backend and a Vite React SPA frontend.

### 1. Set Up Serverless PostgreSQL

For multi-instance or serverless Vercel deployments, configure a managed PostgreSQL instance (e.g., Neon, Supabase, Vercel Postgres, AWS RDS):
1. Create a database in your preferred cloud provider.
2. Ensure connection pooling is enabled (PgBouncer or pooler URL).
3. Copy the pooled connection string (with `?sslmode=require`).

### 2. Configure Environment Variables in Vercel

In the Vercel Project Dashboard:
1. Navigate to **Settings** → **Environment Variables**.
2. Add the production variables (`AGENTSHIELD_ENV=production`, `AGENTSHIELD_ADMIN_KEY`, `AGENTSHIELD_STORAGE_BACKEND=postgres`, `DATABASE_URL`, `GEMINI_API_KEY`, `AGENTSHIELD_CORS_ORIGINS`).

---

## Running the Test Suite

```bash
# Backend unit & integration tests
pytest -v

# Adversarial security test harness
pytest tests/test_adversarial_validation.py -v

# Configuration validation tests
pytest tests/test_config_validation.py -v

# Frontend unit tests
npm --prefix frontend test

# Frontend production build
npm --prefix frontend run build
```

---

## License

Apache 2.0. See `LICENSE` for details.
