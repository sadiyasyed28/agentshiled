import pytest
import inspect
from typing import Dict, Any

from agentshield import (
    Shield,
    PolicyConfiguration,
    ToolBlockedError,
    ToolReviewRequiredError,
    ExecutionResult,
    ExecutionStatus,
)
from agentshield.models import DecisionValue
from agentshield.audit import SQLiteAuditStore


def create_test_shield():
    audit_store = SQLiteAuditStore(db_path=":memory:")
    policy = PolicyConfiguration.from_dict({
        "agents": {
            "test_agent": {
                "allowed_tools": ["add_numbers", "async_multiply", "transfer_funds", "failing_tool"],
                "denied_tools": ["forbidden_tool"],
                "allowed_destinations": ["api.trusted.internal"],
            }
        },
        "tools": {
            "add_numbers": {
                "max_quantity": 100,
                "argument_schema": {
                    "a": "int",
                    "b": "int",
                },
            },
            "async_multiply": {
                "max_quantity": 1000,
            },
            "transfer_funds": {
                "max_amount": 500.0,
                "required_permissions": ["finance:transfer"],
                "allowed_destinations": ["api.trusted.internal"],
            },
            "forbidden_tool": {
                "max_amount": 0,
            },
            "failing_tool": {
                "max_quantity": 10,
            },
        }
    })
    return Shield(audit_store=audit_store, policy=policy, review_ttl_seconds=300.0)


def test_decorator_metadata_and_signature_preservation():
    """Verifies that @shield.protect_tool preserves __name__, docstrings, annotations, and signature."""
    shield = create_test_shield()

    @shield.protect_tool(agent="test_agent")
    def add_numbers(a: int, b: int) -> int:
        """Adds two numbers securely."""
        return a + b

    assert add_numbers.__name__ == "add_numbers"
    assert add_numbers.__doc__ == "Adds two numbers securely."
    assert add_numbers.__shield_tool__ == "add_numbers"
    assert add_numbers.__shield__ is shield

    sig = inspect.signature(add_numbers)
    params = list(sig.parameters.keys())
    assert params == ["a", "b"]
    assert sig.return_annotation is int


def test_allow_executes_exactly_once_and_returns_result():
    """Verifies that an ALLOWed call executes the wrapped function exactly once and returns its result."""
    shield = create_test_shield()
    call_count = {"count": 0}

    @shield.protect_tool(agent="test_agent")
    def add_numbers(a: int, b: int) -> int:
        call_count["count"] += 1
        return a + b

    result = add_numbers(2, 3)
    assert result == 5
    assert call_count["count"] == 1

    # Verify audit record
    audits = shield.audit_store.query(tool="add_numbers")
    assert len(audits) >= 1
    assert any(a.execution_status == "executed" for a in audits)


def test_allow_with_raise_on_blocked_false_returns_execution_result():
    """Verifies raise_on_blocked=False returns an ExecutionResult on ALLOW."""
    shield = create_test_shield()

    @shield.protect_tool(agent="test_agent", raise_on_blocked=False)
    def add_numbers(a: int, b: int) -> int:
        return a + b

    res = add_numbers(10, 20)
    assert isinstance(res, ExecutionResult)
    assert res.decision.decision == DecisionValue.ALLOW
    assert res.execution_status == ExecutionStatus.EXECUTED
    assert res.tool_result == 30


def test_block_never_executes_function():
    """Verifies that BLOCKED actions never invoke the underlying tool function."""
    shield = create_test_shield()
    invoked = {"invoked": False}

    @shield.protect_tool(agent="test_agent")
    def forbidden_tool(data: str) -> str:
        invoked["invoked"] = True
        return "dangerous result"

    with pytest.raises(ToolBlockedError) as exc_info:
        forbidden_tool("exploit")

    assert invoked["invoked"] is False
    assert exc_info.value.decision.decision == DecisionValue.BLOCK
    assert any("explicitly denied" in r for r in exc_info.value.reasons)

    # Audited as not_executed
    audits = shield.audit_store.query(tool="forbidden_tool")
    assert len(audits) >= 1
    assert all(a.execution_status == "not_executed" for a in audits)


def test_block_on_policy_limit_violation():
    """Verifies parameter limits (max_amount) fail closed before function execution."""
    shield = create_test_shield()
    invoked = {"invoked": False}

    @shield.protect_tool(agent="test_agent", permissions=["finance:transfer"])
    def transfer_funds(amount: float, destination: str) -> dict:
        invoked["invoked"] = True
        return {"transferred": amount}

    # $500 max allowed, $900 attempted
    with pytest.raises(ToolBlockedError) as exc_info:
        transfer_funds(900.0, destination="api.trusted.internal")

    assert invoked["invoked"] is False
    assert any("exceeds maximum of 500.0" in r for r in exc_info.value.reasons)


def test_block_on_untrusted_destination():
    """Verifies destination allowlist fails closed without substring bypass."""
    shield = create_test_shield()
    invoked = {"invoked": False}

    @shield.protect_tool(agent="test_agent", permissions=["finance:transfer"])
    def transfer_funds(amount: float, destination: str) -> dict:
        invoked["invoked"] = True
        return {"transferred": amount}

    with pytest.raises(ToolBlockedError) as exc_info:
        transfer_funds(100.0, destination="attacker-api.trusted.internal")

    assert invoked["invoked"] is False
    assert any("Destination hostname" in r for r in exc_info.value.reasons)


def test_block_on_schema_mismatch():
    """Verifies that argument schema violations fail closed before execution."""
    shield = create_test_shield()
    invoked = {"invoked": False}

    @shield.protect_tool(agent="test_agent")
    def add_numbers(a: int, b: int) -> int:
        invoked["invoked"] = True
        return a + b

    # 'a' must be int, pass string
    with pytest.raises(ToolBlockedError) as exc_info:
        add_numbers("not an int", 5)

    assert invoked["invoked"] is False
    assert any("must be of type int" in r for r in exc_info.value.reasons)


def test_block_on_missing_or_unknown_agent():
    """Verifies unknown or empty agent identities fail closed."""
    shield = create_test_shield()
    invoked = {"invoked": False}

    @shield.protect_tool()  # No default agent
    def add_numbers(a: int, b: int) -> int:
        invoked["invoked"] = True
        return a + b

    # Missing agent
    with pytest.raises(ToolBlockedError):
        add_numbers(1, 2)
    assert invoked["invoked"] is False

    # Unknown agent passed via _agent
    with pytest.raises(ToolBlockedError) as exc_info:
        add_numbers(1, 2, _agent="unauthorized_agent")
    assert invoked["invoked"] is False
    assert any("Unknown agent" in r for r in exc_info.value.reasons)


def test_review_never_executes_before_human_approval():
    """Verifies that high-risk REVIEW actions are enqueued and never execute until approved."""
    shield = create_test_shield()
    call_counts = {"count": 0}

    # Configure a tool whose risk or high-value rule triggers REVIEW
    from agentshield.policy.rules import ToolRule
    shield.policy_engine.config.tools["transfer_funds"] = ToolRule(
        tool="transfer_funds",
        max_amount=100000.0,
        required_permissions=["finance:transfer"]
    )

    @shield.protect_tool(agent="test_agent", permissions=["finance:transfer"])
    def transfer_funds(amount: float, destination: str) -> dict:
        call_counts["count"] += 1
        return {"status": "transferred", "amount": amount}

    # Amount > 1000 triggers elevated transaction risk -> REVIEW
    with pytest.raises(ToolReviewRequiredError) as exc_info:
        transfer_funds(5000.0, destination="api.trusted.internal")

    # The function was NOT called!
    assert call_counts["count"] == 0
    assert exc_info.value.decision.decision == DecisionValue.REVIEW
    review_id = exc_info.value.review_id
    assert review_id is not None
    assert review_id.startswith("rev_")

    # Pending in review queue
    pending_queue = shield.get_review_queue()
    assert any(item["review_id"] == review_id for item in pending_queue)

    # Approve the review
    exec_res = shield.approve_review(review_id, approver="alice_supervisor")
    assert exec_res is not None
    assert exec_res.execution_status == ExecutionStatus.EXECUTED
    assert exec_res.tool_result == {"status": "transferred", "amount": 5000.0}
    assert call_counts["count"] == 1

    # Double approval cannot execute again
    exec_again = shield.approve_review(review_id, approver="bob_supervisor")
    assert exec_again is None or exec_again.execution_status == ExecutionStatus.NOT_EXECUTED
    assert call_counts["count"] == 1


@pytest.mark.anyio
async def test_async_protected_tool_execution():
    """Verifies that async functions wrapped with @shield.protect_tool execute safely."""
    shield = create_test_shield()
    invoked = {"count": 0}

    @shield.protect_tool(agent="test_agent")
    async def async_multiply(x: int, y: int) -> int:
        invoked["count"] += 1
        return x * y

    # Async ALLOW
    result = await async_multiply(6, 7)
    assert result == 42
    assert invoked["count"] == 1

    # Async BLOCK
    with pytest.raises(ToolBlockedError):
        await async_multiply(6, 7, _agent="unauthorized_bot")
    assert invoked["count"] == 1  # Not incremented


def test_exception_in_tool_audited_without_accidental_retry():
    """Verifies that exceptions raised inside the tool are audited as 'error' and re-raised cleanly."""
    shield = create_test_shield()
    attempts = {"count": 0}

    @shield.protect_tool(agent="test_agent")
    def failing_tool(msg: str) -> None:
        attempts["count"] += 1
        raise RuntimeError(f"Database connection crashed: {msg}")

    with pytest.raises(RuntimeError, match="Database connection crashed"):
        failing_tool("simulated error")

    # Executed exactly once (never retried silently)
    assert attempts["count"] == 1

    # Audited with error
    audits = shield.audit_store.query(tool="failing_tool")
    assert len(audits) >= 1
    assert any(a.execution_status == "error" for a in audits)


def test_bare_decorator_and_tool_alias():
    """Verifies @shield.protect_tool without arguments and @shield.tool alias."""
    shield = create_test_shield()

    @shield.protect_tool
    def add_numbers(a: int, b: int) -> int:
        return a + b

    # Allowed with explicit _agent
    assert add_numbers(3, 4, _agent="test_agent") == 7

    # @shield.tool alias with explicit allowed tool name
    @shield.tool(name="add_numbers", agent="test_agent")
    def add_alias(a: int, b: int) -> int:
        return a + b

    assert add_alias(3, 4) == 7
