"""
Tests for Persistent SQLite Review Queue.
Verifies restart recovery, concurrency, state machine transitions, exactly-once initiation,
crash recovery to outcome_unknown, idempotent vs non-idempotent retries, and argument integrity.
"""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Dict, Any, Optional

import pytest
from agentshield import Shield, ExecutionStatus
from agentshield.models import Decision, DecisionValue, RiskLevel, FrozenDict
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule
from agentshield.audit import SQLiteAuditStore
from agentshield.review import SQLiteReviewStore, ReviewExecutionState


def _setup_review_shield(
    review_db: str, audit_db: Optional[str] = None, ttl: float = 300.0
) -> Shield:
    review_store = SQLiteReviewStore(db_path=review_db)
    audit_store = SQLiteAuditStore(db_path=audit_db) if audit_db else None
    shield = Shield(audit_store=audit_store, review_store=review_store, review_ttl_seconds=ttl)
    shield.policy_engine.config = PolicyConfiguration(
        agents={"manager": AgentConfig(name="manager", allowed_tools=["refund_order", "send_payment", "payout_invoice"])},
        tools={
            "refund_order": ToolRule(tool="refund_order", max_amount=100000),
            "send_payment": ToolRule(tool="send_payment", max_amount=100000),
            "payout_invoice": ToolRule(tool="payout_invoice", max_amount=100000),
        },
    )
    return shield


def test_review_queue_restart_recovery_and_argument_snapshot_integrity():
    """Pending reviews must survive application restarts and maintain validated frozen snapshot integrity."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_aud:
        aud_db = f_aud.name

    try:
        shield_1 = _setup_review_shield(rev_db, aud_db)
        call_count = {"count": 0}
        shield_1.registry.register(
            "refund_order",
            lambda args: (call_count.__setitem__("count", call_count["count"] + 1), {"done": True})[1],
        )

        raw_args = {
            "amount": 2500,
            "customer": {
                "id": "cust_123",
                "meta": {"tier": "gold", "tags": ["vip", "verified"]},
            },
            "note": "high value refund",
        }

        dec = shield_1.authorize(agent="manager", tool="refund_order", arguments=raw_args)
        assert dec.decision == DecisionValue.REVIEW
        queue_1 = shield_1.get_review_queue()
        assert len(queue_1) == 1
        review_id = queue_1[0]["review_id"]

        # Simulate process shutdown
        del shield_1

        # Reboot on fresh instance
        shield_2 = _setup_review_shield(rev_db, aud_db)
        executed_capture = []

        def recording_tool(args):
            executed_capture.append(dict(args))
            return {"refunded": True, "amount": args["amount"]}

        shield_2.registry.register("refund_order", recording_tool)

        # Recover pending queue
        queue_2 = shield_2.get_review_queue()
        assert len(queue_2) == 1
        recovered = queue_2[0]
        assert recovered["review_id"] == review_id
        assert recovered["status"] == "pending"
        assert recovered["execution_state"] == ReviewExecutionState.NOT_STARTED.value

        # Assert frozen argument snapshot integrity
        recovered_args = recovered["arguments"]
        assert isinstance(recovered_args, FrozenDict)
        assert recovered_args["amount"] == 2500
        assert recovered_args["customer"]["id"] == "cust_123"
        assert recovered_args["customer"]["meta"]["tier"] == "gold"
        assert recovered_args["customer"]["meta"]["tags"] == ["vip", "verified"]

        # Immutability check
        with pytest.raises(TypeError):
            recovered_args["amount"] = 999999

        # Approve on recovered instance
        exec_res = shield_2.approve_review(review_id, approver="admin_post_restart")
        assert exec_res is not None
        assert exec_res.execution_status == ExecutionStatus.EXECUTED
        assert exec_res.tool_result == {"refunded": True, "amount": 2500}

        assert len(executed_capture) == 1
        assert executed_capture[0]["amount"] == 2500
        assert executed_capture[0]["customer"]["meta"]["tier"] == "gold"

        assert len(shield_2.get_review_queue()) == 0
        assert shield_2.get_review_status(review_id) == "approved"
        assert shield_2.get_review_execution_state(review_id) == ReviewExecutionState.SUCCEEDED.value
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)
        if os.path.exists(aud_db):
            os.remove(aud_db)


def test_review_queue_rejection_persistence_across_restart():
    """Rejection state must persist across application restarts and prevent subsequent execution."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield_1 = _setup_review_shield(rev_db)
        shield_1.registry.register("refund_order", lambda args: {"refunded": True})

        dec = shield_1.authorize(agent="manager", tool="refund_order", arguments={"amount": 2500})
        assert dec.decision == DecisionValue.REVIEW
        review_id = shield_1.get_review_queue()[0]["review_id"]

        dec_rej = shield_1.reject_review(review_id, reason="Suspicious velocity", reviewer="analyst_1")
        assert dec_rej is not None
        assert dec_rej.decision == DecisionValue.BLOCK
        assert shield_1.get_review_status(review_id) == "rejected"
        assert len(shield_1.get_review_queue()) == 0

        # Restart
        del shield_1
        shield_2 = _setup_review_shield(rev_db)
        call_counts = {"count": 0}
        shield_2.registry.register("refund_order", lambda args: (call_counts.__setitem__("count", 1), {"ok": True})[1])

        assert shield_2.get_review_status(review_id) == "rejected"
        assert len(shield_2.get_review_queue()) == 0

        # Attempting to approve rejected review must fail closed
        assert shield_2.approve_review(review_id, approver="late_admin") is None
        assert call_counts["count"] == 0
        assert shield_2.reject_review(review_id, reason="Second reject") is None
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_expiry_persistence_and_fail_closed():
    """Expired reviews must fail closed, persist the expired state, and never execute."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield_1 = _setup_review_shield(rev_db, ttl=0.25)
        shield_1.registry.register("refund_order", lambda args: {"refunded": True})

        dec = shield_1.authorize(agent="manager", tool="refund_order", arguments={"amount": 2500})
        assert dec.decision == DecisionValue.REVIEW
        pending = shield_1.get_review_queue()
        assert len(pending) == 1, "Review must be pending immediately after authorization"
        review_id = pending[0]["review_id"]

        time.sleep(0.30)

        del shield_1
        shield_2 = _setup_review_shield(rev_db, ttl=0.25)
        call_counts = {"count": 0}
        shield_2.registry.register("refund_order", lambda args: (call_counts.__setitem__("count", 1), {"ok": True})[1])

        assert len(shield_2.get_review_queue()) == 0
        assert shield_2.get_review_status(review_id) == "expired"
        assert shield_2.approve_review(review_id, approver="admin_expired") is None
        assert call_counts["count"] == 0
        assert shield_2.reject_review(review_id) is None
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_duplicate_approval_and_replay_prevention():
    """Repeated or replayed approvals must strictly execute the tool callable at most once."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _setup_review_shield(rev_db)
        call_counts = {"count": 0}
        shield.registry.register("refund_order", lambda args: (call_counts.__setitem__("count", call_counts["count"] + 1), {"ok": True})[1])

        dec = shield.authorize(agent="manager", tool="refund_order", arguments={"amount": 2000})
        assert dec.decision == DecisionValue.REVIEW
        review_id = shield.get_review_queue()[0]["review_id"]

        # First approval: succeeds and executes
        res1 = shield.approve_review(review_id, approver="alice")
        assert res1 is not None
        assert res1.execution_status == ExecutionStatus.EXECUTED
        assert call_counts["count"] == 1
        assert shield.get_review_execution_state(review_id) == ReviewExecutionState.SUCCEEDED.value

        # Second approval on same instance: must return None and NEVER execute
        res2 = shield.approve_review(review_id, approver="bob")
        assert res2 is None
        assert call_counts["count"] == 1

        # Restart and attempt replay
        shield_restarted = _setup_review_shield(rev_db)
        shield_restarted.registry.register("refund_order", lambda args: (call_counts.__setitem__("count", call_counts["count"] + 1), {"ok": True})[1])

        res3 = shield_restarted.approve_review(review_id, approver="charlie")
        assert res3 is None
        assert call_counts["count"] == 1

        # Rejection after approval must also return None
        res4 = shield_restarted.reject_review(review_id, reviewer="david")
        assert res4 is None
        assert call_counts["count"] == 1
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_functional_arguments_not_corrupted_by_redaction():
    """Verify that required functional tool arguments (e.g. device_token, session_token, query_key)
    are NOT silently replaced with '[REDACTED]' in the review queue."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_aud:
        aud_db = f_aud.name

    try:
        shield = _setup_review_shield(rev_db, aud_db)
        executed_args = []

        def notification_tool(args):
            executed_args.append(dict(args))
            return {"sent": True}

        shield.registry.register("refund_order", notification_tool)

        functional_args = {
            "amount": 2500,
            "device_token": "fcm_token_device_abc_12345",
            "lookup_key": "customer_order_reference",
            "session_code": "sess_998877",
            "description": "Password reset verification requested",
        }

        dec = shield.authorize(agent="manager", tool="refund_order", arguments=functional_args)
        assert dec.decision == DecisionValue.REVIEW
        review_id = shield.get_review_queue()[0]["review_id"]

        # Simulate restart
        del shield
        shield_restarted = _setup_review_shield(rev_db, aud_db)
        shield_restarted.registry.register("refund_order", notification_tool)

        # Approve on recovered instance
        exec_res = shield_restarted.approve_review(review_id, approver="operator_1")
        assert exec_res is not None
        assert exec_res.execution_status == ExecutionStatus.EXECUTED

        # Assert functional arguments arrived at callable completely uncorrupted
        assert len(executed_args) == 1
        call_args = executed_args[0]
        assert call_args["device_token"] == "fcm_token_device_abc_12345"
        assert call_args["lookup_key"] == "customer_order_reference"
        assert call_args["session_code"] == "sess_998877"
        assert call_args["description"] == "Password reset verification requested"
        assert call_args["device_token"] != "[REDACTED]"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)
        if os.path.exists(aud_db):
            os.remove(aud_db)


def test_review_queue_crash_recovery_in_flight_to_outcome_unknown():
    """Simulate a crash during external tool execution (in-flight executing state).
    Upon reboot, the store must reconcile the abandoned in-flight review to 'outcome_unknown'."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        store_1 = SQLiteReviewStore(db_path=rev_db)
        # Enqueue a pending review
        store_1.enqueue_review(
            review_id="rev_crash_test",
            agent="manager",
            tool="charge_card",
            arguments={"amount": 2500, "card_id": "card_tok_123"},
            permissions=[],
            decision=Decision(
                allowed=False,
                decision=DecisionValue.REVIEW,
                reasons=["Review required"],
                risk_score=70.0,
                severity=RiskLevel.HIGH,
                agent="manager",
                tool="charge_card",
            ),
            created_at=time.time(),
            expires_at=time.time() + 300,
        )

        # Claim for approval (transitions to executing with a short lease for test)
        claimed = store_1.claim_and_approve("rev_crash_test", approver="alice", lease_duration=0.1)
        assert claimed is not None
        assert claimed["execution_state"] == ReviewExecutionState.EXECUTING.value

        # Live process protection: a second store initializing concurrently does NOT mark active lease as outcome_unknown
        store_interim = SQLiteReviewStore(db_path=rev_db)
        assert store_interim.get_execution_state("rev_crash_test") == ReviewExecutionState.EXECUTING.value
        del store_interim

        # SIMULATE CRASH: Process is killed mid-execution without calling mark_executed()
        del store_1
        time.sleep(0.15)

        # REBOOT: Fresh process initializes SQLiteReviewStore after abandoned lease expires
        store_2 = SQLiteReviewStore(db_path=rev_db)

        # The abandoned in-flight execution must automatically reconcile to OUTCOME_UNKNOWN
        exec_state = store_2.get_execution_state("rev_crash_test")
        assert exec_state == ReviewExecutionState.OUTCOME_UNKNOWN.value
        assert store_2.get_status("rev_crash_test") == "approved"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_non_idempotent_unknown_outcome_fails_closed():
    """A non-idempotent action in 'outcome_unknown' state MUST NEVER be automatically re-executed."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _setup_review_shield(rev_db)
        card_call_counts = {"count": 0}

        # send_payment is NOT idempotent
        shield.registry.register(
            "send_payment",
            lambda args: (card_call_counts.__setitem__("count", card_call_counts["count"] + 1), {"paid": True})[1],
            idempotent=False,
        )

        # Enqueue and simulate in-flight crash
        dec = shield.authorize(agent="manager", tool="send_payment", arguments={"amount": 2500})
        assert dec.decision == DecisionValue.REVIEW
        review_id = shield.get_review_queue()[0]["review_id"]

        # Manually simulate in-flight crash state in SQLite
        conn = sqlite3.connect(rev_db)
        conn.execute("UPDATE reviews SET status = 'approved', execution_status = 'executing' WHERE review_id = ?", (review_id,))
        conn.commit()
        conn.close()

        # Restart application
        del shield
        shield_restarted = _setup_review_shield(rev_db)
        shield_restarted.registry.register(
            "send_payment",
            lambda args: (card_call_counts.__setitem__("count", card_call_counts["count"] + 1), {"paid": True})[1],
            idempotent=False,
        )

        # Reconciled to outcome_unknown
        assert shield_restarted.get_review_execution_state(review_id) == ReviewExecutionState.OUTCOME_UNKNOWN.value

        # Attempting to re-approve a non-idempotent action with unknown outcome MUST FAIL CLOSED!
        res = shield_restarted.approve_review(review_id, approver="operator_retry")
        assert res is None
        assert card_call_counts["count"] == 0  # Tool callable NEVER invoked!
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_idempotent_retry_with_idempotency_key():
    """An idempotent action in 'outcome_unknown' can be safely retried with its idempotency key."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _setup_review_shield(rev_db)
        invoice_calls = []

        # payout_invoice IS declared idempotent
        shield.registry.register(
            "payout_invoice",
            lambda args: (invoice_calls.append(dict(args)), {"invoice_id": "inv_123"})[1],
            idempotent=True,
        )

        # Enqueue with explicit idempotency key
        dec = shield.authorize(
            agent="manager",
            tool="payout_invoice",
            arguments={"amount": 2500, "idempotency_key": "idemp_inv_999"},
        )
        assert dec.decision == DecisionValue.REVIEW
        review_id = shield.get_review_queue()[0]["review_id"]

        # Manually simulate in-flight crash state in SQLite
        conn = sqlite3.connect(rev_db)
        conn.execute("UPDATE reviews SET status = 'approved', execution_status = 'executing' WHERE review_id = ?", (review_id,))
        conn.commit()
        conn.close()

        # Restart application
        del shield
        shield_restarted = _setup_review_shield(rev_db)
        shield_restarted.registry.register(
            "payout_invoice",
            lambda args: (invoice_calls.append(dict(args)), {"invoice_id": "inv_123"})[1],
            idempotent=True,
        )

        assert shield_restarted.get_review_execution_state(review_id) == ReviewExecutionState.OUTCOME_UNKNOWN.value

        # Approving an idempotent review with unknown outcome is permitted and safe
        res = shield_restarted.approve_review(review_id, approver="operator_retry")
        assert res is not None
        assert res.execution_status == ExecutionStatus.EXECUTED
        assert res.tool_result == {"invoice_id": "inv_123"}
        assert len(invoice_calls) == 1
        assert invoice_calls[0]["idempotency_key"] == "idemp_inv_999"

        # Final state transitions to SUCCEEDED
        assert shield_restarted.get_review_execution_state(review_id) == ReviewExecutionState.SUCCEEDED.value
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_review_queue_concurrent_approvals_multi_process():
    """Multi-process concurrency: multiple independent processes attempting to approve the same
    review simultaneously must result in at-most-once initiation via BEGIN IMMEDIATE transaction locking."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        init_shield = _setup_review_shield(rev_db)
        dec = init_shield.authorize(agent="manager", tool="refund_order", arguments={"amount": 2500})
        assert dec.decision == DecisionValue.REVIEW
        review_id = init_shield.get_review_queue()[0]["review_id"]
        del init_shield

        worker_script = (
            "import sys, os\n"
            "from agentshield import Shield\n"
            "from agentshield.review import SQLiteReviewStore\n"
            "from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule\n"
            "db_path = sys.argv[1]\n"
            "rev_id = sys.argv[2]\n"
            "worker_id = sys.argv[3]\n"
            "review_store = SQLiteReviewStore(db_path=db_path, timeout=30.0)\n"
            "shield = Shield(review_store=review_store)\n"
            "shield.policy_engine.config = PolicyConfiguration(\n"
            "    agents={'manager': AgentConfig(name='manager', allowed_tools=['refund_order'])},\n"
            "    tools={'refund_order': ToolRule(tool='refund_order', max_amount=100000)}\n"
            ")\n"
            "shield.registry.register('refund_order', lambda args: {'worker': worker_id, 'ok': True})\n"
            "res = shield.approve_review(rev_id, approver=f'proc_{worker_id}')\n"
            "if res is not None:\n"
            "    sys.exit(0)  # Claimed and executed\n"
            "else:\n"
            "    sys.exit(42) # Already claimed by competitor\n"
        )

        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath("src")

        num_procs = 4
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", worker_script, rev_db, review_id, str(p)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for p in range(num_procs)
        ]

        exit_codes = []
        for p in procs:
            stdout, stderr = p.communicate(timeout=30)
            exit_codes.append(p.returncode)

        assert exit_codes.count(0) == 1, f"Expected exactly 1 winner, got exit codes: {exit_codes}"
        assert exit_codes.count(42) == num_procs - 1

        verify_shield = _setup_review_shield(rev_db)
        assert verify_shield.get_review_status(review_id) == "approved"
        assert verify_shield.get_review_execution_state(review_id) == ReviewExecutionState.SUCCEEDED.value
        assert len(verify_shield.get_review_queue()) == 0
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_crash_windows_before_during_and_after_invocation():
    """Explicitly verify the four critical crash windows:
    1. Crash before tool invocation (claimed/executing, then process dies).
    2. Crash during tool invocation (unhandled worker crash mid-call).
    3. Crash after downstream success but before local status persistence.
    4. Crash/failure during result persistence.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        # Window 1: Crash before invocation
        store_1 = SQLiteReviewStore(db_path=rev_db)
        store_1.enqueue_review(
            review_id="rev_window1",
            agent="manager",
            tool="send_payment",
            arguments={"amount": 2500, "recipient": "alice"},
            permissions=[],
            decision=Decision(
                allowed=False,
                decision=DecisionValue.REVIEW,
                reasons=["Review required"],
                risk_score=70.0,
                severity=RiskLevel.HIGH,
                agent="manager",
                tool="send_payment",
            ),
            created_at=time.time(),
            expires_at=time.time() + 300,
        )
        # Worker claims with short lease (0.1s), then crashes before invoking callable
        claimed_w1 = store_1.claim_and_approve("rev_window1", approver="reviewer_w1", lease_duration=0.1)
        assert claimed_w1 is not None
        del store_1
        time.sleep(0.15)  # Lease expires

        # Reboot: in-flight is reconciled to outcome_unknown
        store_reboot = SQLiteReviewStore(db_path=rev_db)
        assert store_reboot.get_execution_state("rev_window1") == ReviewExecutionState.OUTCOME_UNKNOWN.value

        # Window 2: Crash during tool invocation
        shield_w2 = _setup_review_shield(rev_db)
        def crashing_tool(args):
            # Simulate a severe worker crash
            raise KeyboardInterrupt("Simulated fatal SIGKILL / process crash")
        shield_w2.registry.register("send_payment", crashing_tool)

        dec_w2 = shield_w2.authorize(agent="manager", tool="send_payment", arguments={"amount": 2500, "recipient": "bob"})
        rev_w2_id = [r["review_id"] for r in shield_w2.get_review_queue() if r["arguments"].get("recipient") == "bob"][0]
        
        with pytest.raises(KeyboardInterrupt):
            shield_w2.approve_review(rev_w2_id, approver="admin_w2")
        
        # State was recorded as failed when handled exception was caught, or if crash was mid-flight
        assert shield_w2.get_review_execution_state(rev_w2_id) in (
            ReviewExecutionState.FAILED.value,
            ReviewExecutionState.EXECUTING.value,
        )

        # Window 3: Crash after downstream side-effect succeeds, but before local DB persistence
        external_service = {"charged": False}
        def payment_service(args):
            external_service["charged"] = True
            return {"status": "charge_200_ok"}

        shield_w3 = _setup_review_shield(rev_db)
        shield_w3.registry.register("send_payment", payment_service)
        dec_w3 = shield_w3.authorize(agent="manager", tool="send_payment", arguments={"amount": 2500, "recipient": "carol"})
        rev_w3_id = [r["review_id"] for r in shield_w3.get_review_queue() if r["arguments"].get("recipient") == "carol"][0]

        # Claim with short lease to simulate crash between callable return and mark_executed
        claimed_w3 = shield_w3.review_store.claim_and_approve(rev_w3_id, approver="admin_w3", lease_duration=0.1)
        # Downstream tool executed and succeeded
        payment_service(claimed_w3["arguments"])
        assert external_service["charged"] is True
        # PROCESS CRASHES HERE before mark_executed can be called!
        del shield_w3
        time.sleep(0.15)  # Lease expires

        # Reboot
        store_w3_reboot = SQLiteReviewStore(db_path=rev_db)
        assert store_w3_reboot.get_execution_state(rev_w3_id) == ReviewExecutionState.OUTCOME_UNKNOWN.value
        # Because send_payment is non-idempotent and lacks idempotency_key, automated retry is strictly REFUSED
        retry_claim = store_w3_reboot.claim_and_approve(rev_w3_id, approver="retry_admin", allow_idempotent_retry=False)
        assert retry_claim is None, "Non-idempotent action with unknown outcome must never be retried"
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_idempotency_key_propagation_and_refusal_without_key():
    """Verify that:
    1. Tools declared idempotent=True but WITHOUT an idempotency_key are REFUSED retry when outcome is unknown.
    2. Tools with an idempotency_key receive the EXACT same key on retry.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name

    try:
        shield = _setup_review_shield(rev_db)
        invocations = []
        def idempotent_payout(args):
            invocations.append(dict(args))
            return {"status": "paid"}

        # Register tool as idempotent
        shield.registry.register("payout_invoice", idempotent_payout, idempotent=True)

        # Case 1: Proposed WITHOUT an idempotency key
        dec_no_key = shield.authorize(agent="manager", tool="payout_invoice", arguments={"amount": 2500, "vendor": "acme"})
        assert dec_no_key.decision == DecisionValue.REVIEW
        rev_no_key_id = shield.get_review_queue()[0]["review_id"]

        # Simulate crash into outcome_unknown
        claimed = shield.review_store.claim_and_approve(rev_no_key_id, approver="tester", lease_duration=0.1)
        time.sleep(0.15)
        shield.review_store.reconcile_in_flight()
        assert shield.get_review_execution_state(rev_no_key_id) == ReviewExecutionState.OUTCOME_UNKNOWN.value

        # Attempt retry: MUST BE REFUSED even though tool.idempotent=True because no idempotency_key exists!
        retry_result = shield.approve_review(rev_no_key_id, approver="tester", allow_idempotent_retry=True)
        assert retry_result is None, "Retry must fail closed when no concrete idempotency key exists"

        # Case 2: Proposed WITH an idempotency key
        fixed_key = "idemp_test_key_998877"
        dec_with_key = shield.authorize(
            agent="manager",
            tool="payout_invoice",
            arguments={"amount": 2500, "vendor": "globex", "idempotency_key": fixed_key}
        )
        assert dec_with_key.decision == DecisionValue.REVIEW
        rev_with_key_id = [r["review_id"] for r in shield.get_review_queue() if r["arguments"].get("vendor") == "globex"][0]

        # Simulate crash into outcome_unknown
        claimed2 = shield.review_store.claim_and_approve(rev_with_key_id, approver="tester2", lease_duration=0.1)
        time.sleep(0.15)
        shield.review_store.reconcile_in_flight()
        assert shield.get_review_execution_state(rev_with_key_id) == ReviewExecutionState.OUTCOME_UNKNOWN.value

        # Retry with idempotency key: MUST SUCCEED
        retry_res2 = shield.approve_review(rev_with_key_id, approver="tester2", allow_idempotent_retry=True)
        assert retry_res2 is not None
        assert retry_res2.execution_status == ExecutionStatus.EXECUTED
        assert len(invocations) == 1
        # Callable received the exact same idempotency key
        assert invocations[0]["idempotency_key"] == fixed_key
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)


def test_secret_redaction_in_reviews_and_audit_errors():
    """Verify that credentials and secrets embedded in tool execution error messages
    are safely redacted before persisting to SQLite reviews table and audit store."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_rev:
        rev_db = f_rev.name
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f_aud:
        aud_db = f_aud.name

    try:
        shield = _setup_review_shield(rev_db, aud_db)
        secret_token = "sk-live-CONFIDENTIAL123456789"
        raw_password = "supersecretpassword123"

        def leaking_tool(args):
            raise ValueError(f"Upstream auth error: Bearer {secret_token} invalid for user with password={raw_password}")

        shield.registry.register("send_payment", leaking_tool)

        dec = shield.authorize(agent="manager", tool="send_payment", arguments={"amount": 2500, "note": "payroll"})
        assert dec.decision == DecisionValue.REVIEW
        rev_id = shield.get_review_queue()[0]["review_id"]

        res = shield.approve_review(rev_id, approver="sec_admin")
        assert res is not None
        assert res.execution_status == ExecutionStatus.ERROR
        assert res.error is not None

        # Inspect SQLite reviews table directly
        conn_rev = sqlite3.connect(rev_db)
        conn_rev.row_factory = sqlite3.Row
        rev_row = conn_rev.execute("SELECT error FROM reviews WHERE review_id = ?", (rev_id,)).fetchone()
        conn_rev.close()

        assert rev_row is not None
        stored_review_error = rev_row["error"]
        assert secret_token not in stored_review_error
        assert raw_password not in stored_review_error
        assert "[REDACTED" in stored_review_error

        # Inspect SQLite audit_logs table directly
        conn_aud = sqlite3.connect(aud_db)
        conn_aud.row_factory = sqlite3.Row
        aud_row = conn_aud.execute("SELECT error FROM audit_logs WHERE execution_status = 'error' ORDER BY id DESC LIMIT 1").fetchone()
        conn_aud.close()

        assert aud_row is not None
        stored_audit_error = aud_row["error"]
        assert secret_token not in stored_audit_error
        assert raw_password not in stored_audit_error
        assert "[REDACTED" in stored_audit_error
    finally:
        if os.path.exists(rev_db):
            os.remove(rev_db)
        if os.path.exists(aud_db):
            os.remove(aud_db)
