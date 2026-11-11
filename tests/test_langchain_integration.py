"""Comprehensive test suite for the AgentShield LangChain integration."""

import asyncio
import sys
from typing import Optional, Type
import pytest
from pydantic import BaseModel, Field

try:
    import langchain_core
    from langchain_core.tools import BaseTool, StructuredTool, tool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

pytest.importorskip(
    "langchain_core",
    reason="langchain-core is not installed in the environment."
)

from agentshield import (
    Shield,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    ToolBlockedError,
    ToolReviewRequiredError,
    ExecutionResult,
    ExecutionStatus,
    protect_langchain_tool,
    AgentShieldTool,
)
from agentshield.models import DecisionValue
from agentshield.audit import SQLiteAuditStore


def create_test_shield():
    audit_store = SQLiteAuditStore(":memory:")
    policy = PolicyConfiguration(
        agents={
            "trusted_agent": AgentConfig(
                name="trusted_agent",
                allowed_tools=["calculator", "search_tool", "async_fetcher", "failing_tool", "transfer_funds", "custom_tool"],
            ),
            "restricted_agent": AgentConfig(
                name="restricted_agent",
                allowed_tools=["calculator"],
            ),
        },
        tools={
            "calculator": ToolRule(
                tool="calculator",
                max_amount=1000.0,
                max_quantity=100.0,
                argument_schema={"a": int, "b": int},
            ),
            "search_tool": ToolRule(
                tool="search_tool",
                allowed_destinations=["api.search.internal"],
            ),
            "async_fetcher": ToolRule(
                tool="async_fetcher",
            ),
            "failing_tool": ToolRule(
                tool="failing_tool",
            ),
            "custom_tool": ToolRule(
                tool="custom_tool",
            ),
            "transfer_funds": ToolRule(
                tool="transfer_funds",
                max_amount=100000.0,
                required_permissions=["finance:transfer"],
            ),
        },
    )
    return Shield(audit_store=audit_store, policy=policy, review_ttl_seconds=300.0)


# ============================================================================
# 1. Tests for packaging and imports without LangChain
# ============================================================================

def test_import_core_without_langchain(monkeypatch):
    """Verifies that core AgentShield imports cleanly when langchain-core is missing,

    and accessing langchain integration produces a clear, actionable ImportError."""
    # Simulate missing langchain_core
    monkeypatch.setitem(sys.modules, "langchain_core", None)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", None)
    # Remove from sys.modules if present to force re-import check
    sys.modules.pop("agentshield.integrations.langchain", None)

    # Core agentshield imports and works fine
    import agentshield
    assert hasattr(agentshield, "Shield")
    assert hasattr(agentshield, "PolicyConfiguration")

    # Calling langchain adapter raises clear ImportError
    with pytest.raises(ImportError) as exc_info:
        import agentshield.integrations.langchain  # noqa: F401
    assert "pip install 'agentshield[langchain]'" in str(exc_info.value) or "pip install agentshield[langchain]" in str(exc_info.value)


def test_adapter_import_with_langchain():
    """Verifies that both direct integration import and lazy top-level import succeed."""
    from agentshield.integrations.langchain import protect_langchain_tool as fn1, AgentShieldTool as cls1
    from agentshield import protect_langchain_tool as fn2, AgentShieldTool as cls2

    assert fn1 is fn2
    assert cls1 is cls2


# ============================================================================
# 2. Schema and metadata preservation
# ============================================================================

def test_wrapping_valid_langchain_tools_and_schema_preservation():
    """Verifies that wrapped tools preserve name, description, args_schema, and args."""
    shield = create_test_shield()

    class CalcInput(BaseModel):
        a: int = Field(description="First integer")
        b: int = Field(description="Second integer")

    @tool(args_schema=CalcInput)
    def calculator(a: int, b: int) -> int:
        """Add two numbers together."""
        return a + b

    wrapped = shield.protect_langchain_tool(calculator, agent="trusted_agent")

    assert isinstance(wrapped, BaseTool)
    assert wrapped.name == "calculator"
    assert wrapped.description == "Add two numbers together."
    assert wrapped.args_schema == CalcInput
    assert "a" in wrapped.args and "b" in wrapped.args
    assert wrapped.agent == "trusted_agent"


def test_wrapping_custom_basetool_subclass():
    """Verifies that custom BaseTool subclasses can be wrapped and preserve metadata."""
    shield = create_test_shield()

    class CustomSearchTool(BaseTool):
        name: str = "custom_tool"
        description: str = "Custom search tool"

        def _run(self, query: str) -> str:
            return f"Found results for: {query}"

    custom = CustomSearchTool()
    wrapped = protect_langchain_tool(custom, shield=shield, agent="trusted_agent")

    assert isinstance(wrapped, BaseTool)
    assert wrapped.name == "custom_tool"
    assert wrapped.description == "Custom search tool"
    res = wrapped.invoke({"query": "agents"})
    assert res == "Found results for: agents"


def test_wrapping_plain_callable():
    """Verifies that raw callables can be wrapped automatically into StructuredTool."""
    shield = create_test_shield()

    def raw_calculator(a: int, b: int) -> int:
        """Raw calculator callable."""
        return a + b

    wrapped = protect_langchain_tool(raw_calculator, shield=shield, agent="trusted_agent", name="calculator")
    assert isinstance(wrapped, BaseTool)
    assert wrapped.name == "calculator"
    assert wrapped.invoke({"a": 5, "b": 7}) == 12


# ============================================================================
# 3. Security Invariant: ALLOW executes exactly once
# ============================================================================

def test_allow_executes_exactly_once():
    """Verifies that an authorized invocation executes the underlying tool exactly once."""
    shield = create_test_shield()
    invocations = []

    @tool
    def calculator(a: int, b: int) -> int:
        """Calculator."""
        invocations.append((a, b))
        return a + b

    wrapped = shield.protect_langchain_tool(calculator, agent="trusted_agent")

    res = wrapped.invoke({"a": 20, "b": 30})
    assert res == 50
    assert len(invocations) == 1
    assert invocations[0] == (20, 30)
    assert wrapped.call_count == 1

    # Check audit log
    records = shield.audit_store.query(tool="calculator")
    assert len(records) >= 1
    assert records[-1].decision == "ALLOW"
    assert records[-1].execution_status == "executed"
    assert records[-1].agent == "trusted_agent"


# ============================================================================
# 4. Security Invariant: BLOCK never executes
# ============================================================================

def test_block_never_executes_on_unauthorized_tool():
    """Verifies that an unauthorized tool is blocked and never executed."""
    shield = create_test_shield()
    invocations = []

    @tool
    def secret_tool(data: str) -> str:
        """Secret tool."""
        invocations.append(data)
        return "classified"

    wrapped = shield.protect_langchain_tool(secret_tool, agent="trusted_agent")

    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.invoke({"data": "probe"})

    assert len(invocations) == 0
    assert wrapped.call_count == 0
    assert "blocked" in str(exc_info.value).lower()
    assert exc_info.value.decision.decision == DecisionValue.BLOCK

    records = shield.audit_store.query(tool="secret_tool")
    assert len(records) >= 1
    assert records[-1].decision == "BLOCK"
    assert records[-1].execution_status == "not_executed"


def test_block_never_executes_on_policy_violation():
    """Verifies that tool exceeding policy limits is blocked and never executed."""
    shield = create_test_shield()
    invocations = []

    @tool
    def calculator(a: int, b: int, amount: float = 0.0) -> int:
        """Calculator with amount."""
        invocations.append((a, b, amount))
        return a + b

    wrapped = shield.protect_langchain_tool(calculator, agent="trusted_agent")

    # Policy limit on calculator is max_amount=1000.0; passing amount=5000.0 violates policy
    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.invoke({"a": 10, "b": 20, "amount": 5000.0})

    assert len(invocations) == 0
    assert wrapped.call_count == 0
    assert exc_info.value.decision.decision == DecisionValue.BLOCK
    assert "exceeds maximum of 1000.0" in str(exc_info.value)


def test_block_destination_restriction():
    """Verifies destination host allowlist enforcement."""
    shield = create_test_shield()
    invocations = []

    @tool
    def search_tool(url: str) -> str:
        """Search."""
        invocations.append(url)
        return "results"

    wrapped = shield.protect_langchain_tool(search_tool, agent="trusted_agent")

    # Untrusted domain blocked
    with pytest.raises(ToolBlockedError):
        wrapped.invoke({"url": "https://attacker.evil.com/leak"})

    assert len(invocations) == 0

    # Trusted domain allowed
    res = wrapped.invoke({"url": "https://api.search.internal/query"})
    assert res == "results"
    assert len(invocations) == 1


# ============================================================================
# 5. Security Invariant: REVIEW never executes before approval
# ============================================================================

def test_review_never_executes_before_human_approval_and_resumes():
    """Verifies that high-risk actions enter the review queue without executing,

    and execute with frozen arguments upon approval."""
    shield = create_test_shield()
    invocations = []

    @tool
    def transfer_funds(amount: float, destination: str) -> dict:
        """Transfer money."""
        invocations.append((amount, destination))
        return {"status": "transferred", "amount": amount, "destination": destination}

    wrapped = shield.protect_langchain_tool(
        transfer_funds,
        agent="trusted_agent",
        permissions=["finance:transfer"],
    )

    # High amount triggers elevated risk -> REVIEW
    with pytest.raises(ToolReviewRequiredError) as exc_info:
        wrapped.invoke({"amount": 5000.0, "destination": "internal_vault"})

    assert len(invocations) == 0
    assert wrapped.call_count == 0
    assert exc_info.value.decision.decision == DecisionValue.REVIEW
    review_id = exc_info.value.review_id
    assert review_id is not None
    assert review_id.startswith("rev_")

    # Review is in pending queue
    queue = shield.get_review_queue()
    assert any(item["review_id"] == review_id for item in queue)

    # Approve the review
    exec_res = shield.approve_review(review_id, approver="alice_supervisor")
    assert exec_res is not None
    assert exec_res.execution_status == ExecutionStatus.EXECUTED
    assert exec_res.tool_result == {"status": "transferred", "amount": 5000.0, "destination": "internal_vault"}
    assert len(invocations) == 1
    assert invocations[0] == (5000.0, "internal_vault")

    # Second approval attempt fails closed (at-most-once initiation)
    exec_again = shield.approve_review(review_id, approver="bob_supervisor")
    assert exec_again is None or exec_again.execution_status == ExecutionStatus.NOT_EXECUTED
    assert len(invocations) == 1


# ============================================================================
# 6. Missing identity, invalid arguments, fail-closed
# ============================================================================

def test_missing_agent_fails_closed():
    """Verifies that omitting agent identity fails closed."""
    shield = create_test_shield()
    invocations = []

    @tool
    def calculator(a: int, b: int) -> int:
        """Calculator."""
        invocations.append((a, b))
        return a + b

    # No agent specified at registration or call time
    wrapped = shield.protect_langchain_tool(calculator, agent=None)

    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.invoke({"a": 1, "b": 2})

    assert len(invocations) == 0
    assert "agent" in str(exc_info.value).lower()
    assert "non-empty string" in str(exc_info.value).lower()


def test_dynamic_overrides_via_kwargs():
    """Verifies that _agent, _permissions, and _correlation_id can be passed dynamically."""
    shield = create_test_shield()
    invocations = []

    @tool
    def calculator(a: int, b: int) -> int:
        """Calculator."""
        invocations.append((a, b))
        return a + b

    # Registered with no default agent
    wrapped = shield.protect_langchain_tool(calculator)

    # Call with dynamic agent override
    res = wrapped.invoke({"a": 10, "b": 20, "_agent": "trusted_agent", "_correlation_id": "sess_42"})
    assert res == 30
    assert len(invocations) == 1

    records = shield.audit_store.query(tool="calculator")
    assert records[-1].agent == "trusted_agent"
    assert records[-1].correlation_id == "sess_42"


# ============================================================================
# 7. Underlying tool exceptions and no accidental retries
# ============================================================================

def test_underlying_tool_exception_audited_and_no_retry():
    """Verifies that when an underlying tool raises, it is audited as an error and re-raised without retrying."""
    shield = create_test_shield()
    invocations = []

    @tool
    def failing_tool(query: str) -> str:
        """Failing tool."""
        invocations.append(query)
        raise ConnectionResetError("Connection dropped by peer")

    wrapped = shield.protect_langchain_tool(failing_tool, agent="trusted_agent")

    with pytest.raises(ConnectionResetError) as exc_info:
        wrapped.invoke({"query": "fetch_data"})

    assert "Connection dropped" in str(exc_info.value)
    # Exactly one execution attempt, no retries
    assert len(invocations) == 1

    records = shield.audit_store.query(tool="failing_tool")
    assert len(records) >= 1
    assert records[-1].execution_status == "error"
    assert "Connection dropped" in (records[-1].error or "")


# ============================================================================
# 8. Async tool execution
# ============================================================================

@pytest.mark.anyio
async def test_async_langchain_tool_execution():
    """Verifies async LangChain tool execution with ainvoke."""
    shield = create_test_shield()
    invocations = []

    @tool
    async def async_fetcher(query: str) -> str:
        """Async fetcher."""
        await asyncio.sleep(0.01)
        invocations.append(query)
        return f"Async result: {query}"

    wrapped = shield.protect_langchain_tool(async_fetcher, agent="trusted_agent")

    res = await wrapped.ainvoke({"query": "distributed_systems"})
    assert res == "Async result: distributed_systems"
    assert len(invocations) == 1
    assert wrapped.call_count == 1


# ============================================================================
# 9. raise_on_blocked=False support
# ============================================================================

def test_raise_on_blocked_false():
    """Verifies that raise_on_blocked=False returns an ExecutionResult instead of raising."""
    shield = create_test_shield()

    @tool
    def calculator(a: int, b: int) -> int:
        """Calculator."""
        return a + b

    # Allowed
    w_allow = shield.protect_langchain_tool(calculator, agent="trusted_agent", raise_on_blocked=False)
    res_allow = w_allow.invoke({"a": 1, "b": 2})
    assert isinstance(res_allow, ExecutionResult)
    assert res_allow.execution_status == ExecutionStatus.EXECUTED
    assert res_allow.tool_result == 3

    # Blocked (unauthorized agent)
    w_block = shield.protect_langchain_tool(calculator, agent="unregistered_agent", raise_on_blocked=False)
    res_block = w_block.invoke({"a": 1, "b": 2})
    assert isinstance(res_block, ExecutionResult)
    assert res_block.execution_status == ExecutionStatus.NOT_EXECUTED
    assert res_block.decision.decision == DecisionValue.BLOCK


# ============================================================================
# 10. AgentShieldTool.from_tool factory method
# ============================================================================

def test_agentshield_tool_from_tool_factory():
    """Verifies that AgentShieldTool.from_tool works identically to protect_langchain_tool."""
    shield = create_test_shield()

    @tool
    def calculator(a: int, b: int) -> int:
        """Calculator."""
        return a + b

    wrapped = AgentShieldTool.from_tool(calculator, shield=shield, agent="trusted_agent")
    assert isinstance(wrapped, AgentShieldTool)
    assert wrapped.invoke({"a": 100, "b": 200}) == 300
