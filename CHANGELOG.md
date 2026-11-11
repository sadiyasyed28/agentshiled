# Changelog

All notable changes to the **AgentShield** Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
