# Changelog

All notable changes to the **AgentShield** Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-16

### SDK Cloud Telemetry, Multi-Tenancy & Distribution Hardening

#### Added
- **Remote Telemetry Exporter (`TelemetryConfig`, `TelemetryExporter`, `TelemetrySpool`)**:
  - Optional cloud telemetry streaming for externally running Python agents.
  - Automatically configured via `AGENTSHIELD_API_URL` and `AGENTSHIELD_API_KEY` or constructor arguments.
  - Asynchronous background worker batching authorization decisions, execution results, and audit events.
  - Persistent bounded disk spooling (`TelemetrySpool`) for offline resiliency and transparent recovery during network outages.
  - Exponential backoff with jitter and configurable queue limits to prevent memory bloat or agent blocking.
  - Zero-overhead, zero-network fallback when telemetry is not configured.
- **Self-Service Customer Onboarding & API Key Management**:
  - Developers can register workspaces and generate hashed API keys (`ash_live_...`).
  - SHA-256 key hashing at rest with constant-time matching and one-time key display at creation.
  - Full key lifecycle operations: listing masked keys (`ash_live_...last4`), revocation, and rotation.
- **Strict Multi-Tenant Isolation**:
  - Authenticated server context derivation for all queries, reviews, agent pauses, and event lookups.
  - Hard rejection (403 Forbidden) for cross-tenant spoofing attempts via headers (`x-tenant-id`) or payload mismatches.
  - Role-Based Access Control: tenant admin data scoping with global admin restriction on platform-wide audit chain verification.
- **Honest Dashboard Data & Metrics**:
  - Removed all production-facing mock fallbacks from KPI sections, decision charts, and review queues.
  - Empty workspace states display genuine onboarding instructions rather than synthetic demo numbers.
- **Release Packaging & Distribution Engineering**:
  - Canonical `MANIFEST.in` explicitly including Python package source and excluding all frontend and local test database files.
  - Fully validated sdist (`.tar.gz`) and wheel (`.whl`) builds passing Twine validation.
  - Clean isolated virtual environment installation and smoke tests.

#### Changed
- Upgraded package version to `0.2.0` across SDK metadata, CLI, and API definitions.
- Resolved in-memory SQLite tenant store isolation using thread-safe shared connection semantics.
- Telemetry status endpoint derives health dynamically from storage health and exporter status.

---

## [0.1.0] - 2026-11-11

### Initial Public Release of the AgentShield Python SDK

#### Added
- **Core Security Engine (`Shield`)**:
  - Deterministic runtime enforcement lifecycle: Propose → Validate → Risk → Policy → Decision → Execute → Audit.
  - Strict fail-closed semantics: unknown tools, unregistered agents, destination mismatches, or schema violations strictly evaluate to `BLOCK`.
  - Execution invariants: `BLOCK` invokes the tool callable 0 times; `ALLOW` invokes the tool exactly once per authorized proposal.
- **Declarative Policy Configuration (`PolicyConfiguration`)**:
  - Dictionary/JSON schema loading (`PolicyConfiguration.from_dict()`).
  - YAML policy loading and exporting (`PolicyConfiguration.from_yaml()`, `PolicyConfiguration.to_yaml()`) via optional `agentshield[yaml]`.
  - Immutable policy version hashing (`version_hash`) for tamper-evident audit trails.
- **Decorator-Based Tool Protection (`@shield.protect_tool`)**:
  - Seamlessly wrap existing Python functions and methods.
  - Preserves function signature and docstrings via `functools.wraps`.
  - Supports both synchronous and asynchronous callables.
  - Raises typed exceptions: `ToolBlockedError` and `ToolReviewRequiredError`.
- **Framework Integrations**:
  - **LangChain Adapter** (`agentshield.integrations.langchain` / `shield.protect_langchain_tool`): Wraps LangChain `BaseTool`, `@tool`, and `StructuredTool`. Preserves tool names, descriptions, and argument schemas.
  - **CrewAI Adapter** (`agentshield.integrations.crewai` / `shield.protect_crewai_tool`): Wraps CrewAI tools and custom callables with deterministic runtime security and approval workflows.
- **Audit & Cryptographic Ledger**:
  - Pluggable `AuditStore` interface with default `SQLiteAuditStore`.
  - Cryptographically chained SHA-256 ledger linked to a genesis hash to detect tampering.
  - Autonomous secret redaction across audit logs, review arguments, and event feeds.
- **Human-in-the-Loop Review Queue**:
  - Pluggable `ReviewStore` interface with atomic claims and fencing tokens.
  - Resume-on-approval semantics: executes pre-validated frozen arguments exactly once upon supervisor approval.
- **Pluggable Storage Backends**:
  - High-concurrency SQLite storage with WAL mode and `BEGIN IMMEDIATE` transactions.
  - Production PostgreSQL storage (`agentshield[postgres]`) with advisory schema locking and `SELECT ... FOR UPDATE` row locks.
- **Reliability & Resource Limits**:
  - Configurable rate limiters (in-memory, SQLite, PostgreSQL).
  - Tool execution timeouts and payload size limits.
  - Session call budget and token budget trackers.
  - Circuit breakers for external LLM analyst providers.
  - Cyclic loop detection (`LoopDetector`) to prevent runaway agent loops.
- **SDK Packaging Isolation**:
  - Minimal core dependencies: `pydantic>=2.0` only.
  - Optional extras: `yaml`, `langchain`, `crewai`, `server`, `postgres`, `gemini`, `all`.
  - Lazy loading for optional integrations with clear, actionable installation instructions when missing.
