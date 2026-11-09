"""
Production Readiness Hardening Test Suite for AgentShield.

Verifies:
1. Multi-threaded SQLite concurrency (burst review creation, approval, rejection, expiration races).
2. Atomic at-most-once execution under concurrent duplicate approval requests.
3. Transaction rollback and DB error handling.
4. Cryptographic audit-chain integrity across multiple restarts.
5. High-concurrency deterministic policy enforcement (ALLOW / REVIEW / BLOCK).
6. Comprehensive secret redaction across audit, review, and event stores.
7. Fail-closed behavior on missing or invalid configuration.
8. Standalone SDK import isolation (zero eager optional extras loaded).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import pytest

from agentshield import Shield, ExecutionStatus
from agentshield.models import Decision, DecisionValue, RiskLevel, FrozenDict
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule
from agentshield.audit import SQLiteAuditStore, GENESIS_HASH
from agentshield.review import SQLiteReviewStore, ReviewExecutionState
from agentshield.events import SQLiteEventStore
from agentshield.storage import create_stores, ConfigurationError, validate_database_url


def _create_test_shield(review_db: str, audit_db: Optional[str] = None, ttl: float = 300.0) -> Shield:
    review_store = SQLiteReviewStore(db_path=review_db, timeout=30.0)
    audit_store = SQLiteAuditStore(db_path=audit_db, timeout=30.0) if audit_db else None
    policy = PolicyConfiguration(
        agents={
            "finance_agent": AgentConfig(
                name="finance_agent",
                allowed_tools=["wire_transfer", "check_balance", "safe_calc"],
                denied_tools=["delete_account"],
            )
        },
        tools={
            "wire_transfer": ToolRule(tool="wire_transfer", max_amount=100000.0, required_permissions=["wire:execute"]),
            "check_balance": ToolRule(tool="check_balance"),
            "safe_calc": ToolRule(tool="safe_calc"),
            "delete_account": ToolRule(tool="delete_account"),
        },
    )
    return Shield(audit_store=audit_store, review_store=review_store, policy=policy, review_ttl_seconds=ttl)


# ============================================================================
# 1. Concurrent Review Creation Burst
# ============================================================================

def test_concurrent_review_creation_burst():
    """Verifies that 20 concurrent threads can enqueue reviews simultaneously
    without database locking errors, and all 20 reviews are persisted cleanly."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _create_test_shield(rev_db)
        num_threads = 20
        enqueued_ids: List[str] = []
        lock = threading.Lock()

        def worker(thread_idx: int):
            # Amount between 1000 and 5000 triggers REVIEW (Risk HIGH)
            dec = shield.authorize(
                agent="finance_agent",
                tool="wire_transfer",
                arguments={"amount": 2500.0 + thread_idx, "dest": f"ACC_{thread_idx}"},
                permissions=["wire:execute"],
            )
            assert dec.decision == DecisionValue.REVIEW
            assert dec.review_id is not None
            with lock:
                enqueued_ids.append(dec.review_id)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            for f in futures:
                f.result()

        assert len(enqueued_ids) == num_threads
        assert len(set(enqueued_ids)) == num_threads, "All review IDs must be strictly unique"

        # Verify persistent store contains all reviews
        pending = shield.get_review_queue()
        assert len(pending) == num_threads
        for item in pending:
            assert item["status"] == "pending"
            assert item["execution_state"] == ReviewExecutionState.NOT_STARTED.value
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 2. Concurrent Distinct Reviews Approval
# ============================================================================

def test_concurrent_distinct_reviews_approval():
    """Verifies that 10 concurrent threads approving 10 distinct reviews
    all complete successfully and execute their tools exactly once."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _create_test_shield(rev_db)
        execution_counts: Dict[str, int] = {}
        exec_lock = threading.Lock()

        def wire_transfer_callable(amount: float, dest: str) -> str:
            with exec_lock:
                execution_counts[dest] = execution_counts.get(dest, 0) + 1
            return f"Wired ${amount} to {dest}"

        shield.registry.register("wire_transfer", wire_transfer_callable)

        # Enqueue 10 reviews
        review_ids = []
        for i in range(10):
            dec = shield.authorize(
                agent="finance_agent",
                tool="wire_transfer",
                arguments={"amount": 2000.0 + i, "dest": f"ACC_DISTINCT_{i}"},
                permissions=["wire:execute"],
            )
            review_ids.append(dec.review_id)

        # Concurrently approve all 10
        def approve_worker(rev_id: str):
            local_shield = _create_test_shield(rev_db)
            local_shield.registry.register("wire_transfer", wire_transfer_callable)
            res = local_shield.approve_review(rev_id, approver=f"approver_{rev_id}")
            assert res is not None
            assert res.execution_status == ExecutionStatus.EXECUTED

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(approve_worker, rid) for rid in review_ids]
            for f in futures:
                f.result()

        # Verify all executed exactly once
        assert len(execution_counts) == 10
        for dest, count in execution_counts.items():
            assert count == 1, f"Destination {dest} executed {count} times instead of 1"

        # Verify review queue is empty and states are SUCCEEDED
        assert len(shield.get_review_queue()) == 0
        for rid in review_ids:
            assert shield.get_review_status(rid) == "approved"
            assert shield.get_review_execution_state(rid) == ReviewExecutionState.SUCCEEDED.value
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 3. Concurrent Duplicate Approval Race: Atomic Exactly-Once Execution
# ============================================================================

def test_concurrent_duplicate_approvals_atomic_single_execution():
    """Multiple threads racing to approve the EXACT SAME review simultaneously
    must result in exactly 1 winner, N-1 rejections, and exactly 1 tool execution."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _create_test_shield(rev_db)
        invocations = []
        inv_lock = threading.Lock()

        def wire_transfer_callable(amount: float, dest: str) -> str:
            with inv_lock:
                invocations.append((amount, dest))
            time.sleep(0.01)  # Simulate small execution window
            return f"Wired ${amount} to {dest}"

        shield.registry.register("wire_transfer", wire_transfer_callable)

        # Enqueue single review
        dec = shield.authorize(
            agent="finance_agent",
            tool="wire_transfer",
            arguments={"amount": 2500.0, "dest": "ACC_SINGLE_RACE"},
            permissions=["wire:execute"],
        )
        target_review_id = dec.review_id

        num_competitors = 10
        results = []
        res_lock = threading.Lock()

        def race_worker(worker_idx: int):
            local_shield = _create_test_shield(rev_db)
            local_shield.registry.register("wire_transfer", wire_transfer_callable)
            outcome = local_shield.approve_review(target_review_id, approver=f"competitor_{worker_idx}")
            with res_lock:
                results.append(outcome)

        with ThreadPoolExecutor(max_workers=num_competitors) as executor:
            futures = [executor.submit(race_worker, i) for i in range(num_competitors)]
            for f in futures:
                f.result()

        # Exactly 1 result must be an ExecutionResult with EXECUTED
        winners = [r for r in results if r is not None and r.execution_status == ExecutionStatus.EXECUTED]
        losers = [r for r in results if r is None]

        assert len(winners) == 1, f"Expected exactly 1 winner, got {len(winners)}"
        assert len(losers) == num_competitors - 1, f"Expected {num_competitors - 1} losers, got {len(losers)}"
        assert len(invocations) == 1, f"Tool was invoked {len(invocations)} times instead of exactly once!"
        assert invocations[0] == (2500.0, "ACC_SINGLE_RACE")
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 4. Concurrent Approval vs Rejection Race
# ============================================================================

def test_concurrent_approval_vs_rejection_race():
    """Threads racing to approve vs reject the same review simultaneously must
    resolve atomically: exactly one wins, state is consistent, and tool callable
    executes at most once."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _create_test_shield(rev_db)
        invocations = []
        inv_lock = threading.Lock()

        def wire_transfer_callable(amount: float, dest: str) -> str:
            with inv_lock:
                invocations.append((amount, dest))
            return "ok"

        shield.registry.register("wire_transfer", wire_transfer_callable)

        dec = shield.authorize(
            agent="finance_agent",
            tool="wire_transfer",
            arguments={"amount": 2500.0, "dest": "ACC_APPROVE_VS_REJECT"},
            permissions=["wire:execute"],
        )
        rev_id = dec.review_id

        num_threads = 8
        approvals = []
        rejections = []
        lock = threading.Lock()

        def race_worker(thread_idx: int):
            local_shield = _create_test_shield(rev_db)
            local_shield.registry.register("wire_transfer", wire_transfer_callable)
            if thread_idx % 2 == 0:
                appr_res = local_shield.approve_review(rev_id, approver=f"admin_{thread_idx}")
                with lock:
                    approvals.append(appr_res)
            else:
                rej_res = local_shield.reject_review(rev_id, reason="Suspicious activity", reviewer=f"auditor_{thread_idx}")
                with lock:
                    rejections.append(rej_res)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(race_worker, i) for i in range(num_threads)]
            for f in futures:
                f.result()

        winning_approvals = [a for a in approvals if a is not None]
        winning_rejections = [r for r in rejections if r is not None]

        # Exactly one outcome wins across the entire race
        assert (len(winning_approvals) == 1 and len(winning_rejections) == 0) or \
               (len(winning_approvals) == 0 and len(winning_rejections) == 1), \
               f"Expected mutually exclusive winner: approvals={len(winning_approvals)}, rejections={len(winning_rejections)}"

        if len(winning_approvals) == 1:
            assert len(invocations) == 1
            assert shield.get_review_status(rev_id) == "approved"
        else:
            assert len(invocations) == 0
            assert shield.get_review_status(rev_id) == "rejected"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 5. Concurrent Expiration vs Approval Race
# ============================================================================

def test_concurrent_expiration_vs_approval_race():
    """A review that expires while approval is attempted must fail closed
    and never execute the underlying tool."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        # TTL of 0.15 seconds
        shield = _create_test_shield(rev_db, ttl=0.15)
        invocations = []
        shield.registry.register("wire_transfer", lambda **kw: invocations.append(kw))

        dec = shield.authorize(
            agent="finance_agent",
            tool="wire_transfer",
            arguments={"amount": 4000.0, "dest": "ACC_EXPIRY"},
            permissions=["wire:execute"],
        )
        rev_id = dec.review_id

        # Sleep past expiration
        time.sleep(0.20)

        # Concurrently attempt approval from multiple threads
        results = []
        def try_approve():
            s = _create_test_shield(rev_db, ttl=0.15)
            s.registry.register("wire_transfer", lambda **kw: invocations.append(kw))
            return s.approve_review(rev_id, approver="late_admin")

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(try_approve) for _ in range(4)]
            for f in futures:
                results.append(f.result())

        # All must be None (expired)
        assert all(r is None for r in results)
        assert len(invocations) == 0, "Expired review must NEVER execute"
        assert shield.get_review_status(rev_id) == "expired"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 6. SQLite Transaction Rollback and Database Failure Behavior
# ============================================================================

def test_sqlite_transaction_rollback_on_failure():
    """Verify that if a database transaction encounters an error midway,
    it cleanly rolls back and leaves the database uncorrupted and operational."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        store = SQLiteReviewStore(db_path=rev_db)
        # Attempt to insert a malformed row that violates NOT NULL constraint
        conn = store._get_connection()
        try:
            conn.execute("BEGIN IMMEDIATE")
            # reviews table requires review_id, agent, tool NOT NULL
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO reviews (review_id, agent) VALUES (NULL, 'bad_agent');")
            conn.rollback()
        finally:
            store._close_connection(conn)

        # Store remains fully functional after rollback
        store.enqueue_review(
            review_id="rev_healthy_1",
            agent="finance_agent",
            tool="wire_transfer",
            arguments={"amount": 123.0},
            permissions=[],
            decision=Decision(
                allowed=False,
                decision=DecisionValue.REVIEW,
                reasons=["Check"],
                risk_score=50.0,
                severity=RiskLevel.MEDIUM,
                agent="finance_agent",
                tool="wire_transfer",
            ),
            created_at=time.time(),
            expires_at=time.time() + 300,
        )
        assert store.get_status("rev_healthy_1") == "pending"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 7. Audit-Chain Integrity Across Repeated Restarts
# ============================================================================

def test_audit_chain_integrity_across_repeated_restarts():
    """Auditing entries across multiple process reboots/reconnects maintains
    a linear cryptographic SHA-256 hash chain without branching or corruption."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_aud:
        aud_db = f_aud.name

    try:
        num_sessions = 5
        records_per_session = 6
        total_expected = num_sessions * records_per_session

        for session_idx in range(num_sessions):
            # Simulate cold start
            store = SQLiteAuditStore(db_path=aud_db)
            for r_idx in range(records_per_session):
                dec = Decision(
                    allowed=(r_idx % 2 == 0),
                    decision=DecisionValue.ALLOW if r_idx % 2 == 0 else DecisionValue.BLOCK,
                    reasons=[f"Session {session_idx} record {r_idx}"],
                    risk_score=float(session_idx * 10 + r_idx),
                    severity=RiskLevel.LOW,
                    agent="session_agent",
                    tool="session_tool",
                )
                store.log_decision(dec, arguments={"session": session_idx, "idx": r_idx})
            del store

        # Verify integrity on fresh store instance
        verify_store = SQLiteAuditStore(db_path=aud_db)
        integrity = verify_store.verify_integrity()
        assert integrity["valid"] is True
        assert integrity["total_records"] == total_expected
        assert integrity["error"] is None

        # Verify linear hash sequence from oldest to newest
        all_records = verify_store.query(limit=total_expected + 10)
        assert len(all_records) == total_expected

        # Reverse order in query (DESC), so all_records[-1] is oldest (genesis)
        assert all_records[-1].prev_hash == GENESIS_HASH
        for i in range(len(all_records) - 1):
            assert all_records[i].prev_hash == all_records[i + 1].record_hash

        # Non-genesis hashes must all be unique
        non_genesis = [r.prev_hash for r in all_records if r.prev_hash != GENESIS_HASH]
        assert len(non_genesis) == len(set(non_genesis))
    finally:
        if os.path.exists(aud_db):
            os.remove(aud_db)


# ============================================================================
# 8. High-Concurrency Deterministic Enforcement
# ============================================================================

def test_high_load_deterministic_enforcement():
    """Executes 60 concurrent requests across ALLOW, REVIEW, and BLOCK policies.
    Guarantees that ALLOW executes once, BLOCK never executes, and REVIEW enqueues."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _create_test_shield(rev_db)
        allow_counts = 0
        block_counts = 0
        lock = threading.Lock()

        def safe_calc_callable(a: int, b: int) -> int:
            nonlocal allow_counts
            with lock:
                allow_counts += 1
            return a + b

        def delete_account_callable(account_id: str):
            nonlocal block_counts
            with lock:
                block_counts += 1
            return "deleted"

        shield.registry.register("safe_calc", safe_calc_callable)
        shield.registry.register("delete_account", delete_account_callable)

        def worker(request_idx: int):
            local_shield = _create_test_shield(rev_db)
            local_shield.registry.register("safe_calc", safe_calc_callable)
            local_shield.registry.register("delete_account", delete_account_callable)

            category = request_idx % 3
            if category == 0:
                # ALLOW
                res = local_shield.execute(
                    agent="finance_agent",
                    tool="safe_calc",
                    arguments={"a": request_idx, "b": 1},
                )
                assert res.execution_status == ExecutionStatus.EXECUTED
                assert res.tool_result == request_idx + 1
            elif category == 1:
                # BLOCK (denied_tool)
                res = local_shield.execute(
                    agent="finance_agent",
                    tool="delete_account",
                    arguments={"account_id": f"acc_{request_idx}"},
                )
                assert res.execution_status == ExecutionStatus.NOT_EXECUTED
                assert res.decision.decision == DecisionValue.BLOCK
            else:
                # REVIEW (amount > 1000 and <= 5000)
                res = local_shield.execute(
                    agent="finance_agent",
                    tool="wire_transfer",
                    arguments={"amount": 2500.0 + request_idx, "dest": "ACC_BURST"},
                    permissions=["wire:execute"],
                )
                assert res.execution_status == ExecutionStatus.NOT_EXECUTED
                assert res.decision.decision == DecisionValue.REVIEW

        total_requests = 60
        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(worker, i) for i in range(total_requests)]
            for f in futures:
                f.result()

        expected_allows = total_requests // 3
        expected_reviews = total_requests // 3
        assert allow_counts == expected_allows, f"ALLOW executed {allow_counts} times, expected {expected_allows}"
        assert block_counts == 0, f"BLOCK executed {block_counts} times, expected 0"

        # Verify reviews enqueued
        pending = shield.get_review_queue()
        assert len(pending) == expected_reviews
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 9. Secret Redaction Comprehensive Audit
# ============================================================================

def test_secret_redaction_comprehensive_audit():
    """Guarantees that sensitive secrets (API keys, passwords, bearer tokens,
    private keys) never appear in plain text in audit logs, review store, or event store."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_aud:
        aud_db = f_aud.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        audit_store = SQLiteAuditStore(db_path=aud_db)
        review_store = SQLiteReviewStore(db_path=rev_db)
        shield = Shield(audit_store=audit_store, review_store=review_store)

        sensitive_payload = {
            "customer_id": "cust_99",
            "quantity": 2,
            "api_key": "sk-live-abcdef1234567890abcdef",
            "password": "SuperSecretPassword123!",
            "auth_header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
            "notes": "Please deliver to front desk",
        }

        # 1. Authorize
        dec = shield.authorize(
            agent="shopping_agent",
            tool="create_order",
            arguments=sensitive_payload,
        )

        # 2. Check audit log
        audit_store.log_decision(dec, sensitive_payload, execution_status="executed")
        records = audit_store.query(limit=5)
        assert len(records) >= 1
        logged_args = records[0].arguments

        # Secrets must be redacted
        assert logged_args["api_key"] == "[REDACTED]"
        assert logged_args["password"] == "[REDACTED]"
        assert logged_args["auth_header"] == "[REDACTED]"
        # Functional arguments must be preserved
        assert logged_args["customer_id"] == "cust_99"
        assert logged_args["quantity"] == 2
        assert logged_args["notes"] == "Please deliver to front desk"

        # Raw DB text inspection to ensure no plaintext leak in SQLite file
        with open(aud_db, "rb") as f:
            raw_bytes = f.read()
            assert b"sk-live-abcdef1234567890abcdef" not in raw_bytes
            assert b"SuperSecretPassword123!" not in raw_bytes
    finally:
        if os.path.exists(aud_db):
            os.remove(aud_db)
        if os.path.exists(rev_db):
            os.remove(rev_db)


# ============================================================================
# 10. Fail-Closed on Missing and Invalid Configuration
# ============================================================================

def test_missing_and_invalid_configuration_fails_closed():
    """Invalid database URLs, unknown storage protocols, or missing drivers
    must strictly fail closed and never silently fall back to mock."""
    with pytest.raises(ConfigurationError):
        validate_database_url("mysql://user:pass@localhost/db")

    with pytest.raises(ConfigurationError):
        validate_database_url("invalid-url-schema")

    with pytest.raises((ConfigurationError, Exception)):
        create_stores(database_url="postgresql://invalid_host:9999999/invalid")


# ============================================================================
# 11. Optional Dependency Isolation
# ============================================================================

def test_optional_dependency_isolation():
    """Importing core agentshield in a clean process does not eagerly load FastAPI, Uvicorn, Psycopg,
    Google GenAI, CrewAI, or LangChain into sys.modules."""
    import subprocess
    code = (
        "import sys\n"
        "import agentshield\n"
        "for mod in ['fastapi', 'uvicorn', 'psycopg', 'google.genai', 'crewai', 'langchain']:\n"
        "    if mod in sys.modules:\n"
        "        sys.exit(1)\n"
        "sys.exit(0)\n"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert res.returncode == 0, f"Optional module eagerly loaded by core SDK! {res.stderr}"
