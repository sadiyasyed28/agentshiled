"""Comprehensive test suite for the AgentShield CrewAI integration."""

import asyncio
import sys
import types
from typing import Any, Optional, Type
import pytest
from pydantic import BaseModel, Field, ConfigDict

from agentshield import (
    Shield,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    ToolBlockedError,
    ToolReviewRequiredError,
    ExecutionResult,
    ExecutionStatus,
)
from agentshield.models import DecisionValue
from agentshield.audit import SQLiteAuditStore


# ============================================================================
# Mock CrewAI BaseTool infrastructure
# ============================================================================

class MockCrewAIBaseTool(BaseModel):
    """Mock of crewai.tools.BaseTool for testing environments where crewai is not installed."""
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    args_schema: Optional[Type[BaseModel]] = Field(default=None, description="Tool schema")
    result_as_answer: bool = Field(default=False, description="Whether tool result is final answer")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        return await self._arun(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


@pytest.fixture(autouse=True)
def inject_crewai_modules(monkeypatch):
    """Ensures mock crewai modules are injected during tests unless intentionally removed."""
    mock_crewai_tools = types.ModuleType("crewai.tools")
    mock_crewai_tools.BaseTool = MockCrewAIBaseTool
    mock_crewai = types.ModuleType("crewai")
    mock_crewai.tools = mock_crewai_tools
    mock_crewai.BaseTool = MockCrewAIBaseTool

    monkeypatch.setitem(sys.modules, "crewai", mock_crewai)
    monkeypatch.setitem(sys.modules, "crewai.tools", mock_crewai_tools)
    # Ensure fresh import if module was loaded
    sys.modules.pop("agentshield.integrations.crewai", None)
    yield


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
# 1. Tests for packaging and imports without CrewAI
# ============================================================================

def test_import_core_without_crewai(monkeypatch):
    """Verifies that core AgentShield imports cleanly when crewai is missing,
    and accessing crewai integration produces a clear, actionable ImportError.
    """
    monkeypatch.delitem(sys.modules, "crewai", raising=False)
    monkeypatch.delitem(sys.modules, "crewai.tools", raising=False)
    sys.modules.pop("agentshield.integrations.crewai", None)

    import agentshield
    assert hasattr(agentshield, "Shield")
    assert hasattr(agentshield, "PolicyConfiguration")

    with pytest.raises(ImportError) as exc_info:
        import agentshield.integrations.crewai  # noqa: F401
    assert "pip install 'agentshield[crewai]'" in str(exc_info.value)


def test_adapter_import_with_crewai():
    """Verifies that both direct integration import and lazy top-level import succeed."""
    from agentshield.integrations.crewai import protect_crewai_tool as fn1, AgentShieldCrewAITool as cls1
    from agentshield import protect_crewai_tool as fn2, AgentShieldCrewAITool as cls2

    assert fn1 is fn2
    assert cls1 is cls2


# ============================================================================
# 2. Schema, metadata preservation, and registration
# ============================================================================

def test_wrapping_crewai_tool_and_schema_preservation():
    """Verifies that wrapped tools preserve name, description, args_schema, and result_as_answer."""
    from agentshield.integrations.crewai import protect_crewai_tool, AgentShieldCrewAITool

    shield = create_test_shield()

    class CalcInput(BaseModel):
        a: int = Field(description="First integer")
        b: int = Field(description="Second integer")

    class CalcTool(MockCrewAIBaseTool):
        name: str = "calculator"
        description: str = "Add two numbers"
        args_schema: Type[BaseModel] = CalcInput
        result_as_answer: bool = True

        def _run(self, a: int, b: int) -> int:
            return a + b

    tool = CalcTool()
    wrapped = protect_crewai_tool(tool, shield=shield, agent="trusted_agent")

    assert isinstance(wrapped, AgentShieldCrewAITool)
    assert issubclass(AgentShieldCrewAITool, MockCrewAIBaseTool)
    assert wrapped.name == "calculator"
    assert wrapped.description == "Add two numbers"
    assert wrapped.args_schema == CalcInput
    assert wrapped.result_as_answer is True
    assert wrapped.agent == "trusted_agent"

    # Verify registration in shield.registry
    assert shield.registry.has_tool("calculator")


def test_wrapping_callable_and_overrides():
    """Verifies wrapping a plain callable with metadata overrides."""
    from agentshield.integrations.crewai import AgentShieldCrewAITool

    shield = create_test_shield()

    def my_calc(a: int, b: int) -> int:
        """Original docstring"""
        return a * b

    wrapped = AgentShieldCrewAITool.from_tool(
        my_calc,
        shield=shield,
        name="calculator",
        description="Multiplies numbers",
        agent="trusted_agent",
    )

    assert wrapped.name == "calculator"
    assert wrapped.description == "Multiplies numbers"
    assert wrapped.run(a=5, b=6) == 30


# ============================================================================
# 3. ALLOW execution semantics
# ============================================================================

def test_allowed_tool_execution_success():
    """Verifies that allowed tool execution succeeds, invokes tool exactly once, and audits."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    executed_count = 0

    class CalcTool(MockCrewAIBaseTool):
        name: str = "calculator"
        description: str = "Add two numbers"

        def _run(self, a: int, b: int) -> int:
            nonlocal executed_count
            executed_count += 1
            return a + b

    wrapped = protect_crewai_tool(CalcTool(), shield=shield, agent="trusted_agent")

    # Invocations via run, _run, and __call__
    res1 = wrapped.run(a=10, b=20)
    assert res1 == 30
    assert executed_count == 1
    assert wrapped.call_count == 1

    res2 = wrapped._run(a=5, b=5)
    assert res2 == 10
    assert executed_count == 2
    assert wrapped.call_count == 2

    res3 = wrapped(a=1, b=2)
    assert res3 == 3
    assert executed_count == 3
    assert wrapped.call_count == 3

    # Check audit log
    records = shield.audit_store.query(tool="calculator")
    assert len(records) >= 3
    for rec in records[-3:]:
        assert rec.tool == "calculator"
        assert rec.agent == "trusted_agent"
        assert rec.decision == "ALLOW"
        assert rec.execution_status == "executed"


def test_allowed_tool_execution_no_raise_mode():
    """Verifies raise_on_blocked=False returns ExecutionResult on success."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()

    class CalcTool(MockCrewAIBaseTool):
        name: str = "calculator"
        description: str = "Add two numbers"

        def _run(self, a: int, b: int) -> int:
            return a + b

    wrapped = protect_crewai_tool(
        CalcTool(),
        shield=shield,
        agent="trusted_agent",
        raise_on_blocked=False,
    )

    result = wrapped.run(a=10, b=20)
    assert isinstance(result, ExecutionResult)
    assert result.decision.decision == DecisionValue.ALLOW
    assert result.execution_status == ExecutionStatus.EXECUTED
    assert result.tool_result == 30


# ============================================================================
# 4. BLOCK enforcement and fail-closed semantics
# ============================================================================

def test_blocked_unauthorized_agent():
    """Verifies that an agent not allowed to call the tool is blocked without execution."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    executed_count = 0

    class SearchTool(MockCrewAIBaseTool):
        name: str = "search_tool"
        description: str = "Search tool"

        def _run(self, destination: str) -> str:
            nonlocal executed_count
            executed_count += 1
            return f"searched {destination}"

    # restricted_agent is not allowed to use search_tool
    wrapped = protect_crewai_tool(SearchTool(), shield=shield, agent="restricted_agent")

    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.run(destination="api.search.internal")

    assert "blocked" in str(exc_info.value).lower()
    assert exc_info.value.decision.decision == DecisionValue.BLOCK
    assert executed_count == 0
    assert wrapped.call_count == 0

    records = shield.audit_store.query(tool="search_tool")
    assert any(r.execution_status == "not_executed" and r.decision == "BLOCK" for r in records)


def test_blocked_policy_violation_max_amount():
    """Verifies parameter validation: exceeding max_amount blocks execution."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    executed_count = 0

    class CalcTool(MockCrewAIBaseTool):
        name: str = "calculator"
        description: str = "Calculator"

        def _run(self, a: int, b: int, amount: float = 0.0) -> int:
            nonlocal executed_count
            executed_count += 1
            return a + b

    wrapped = protect_crewai_tool(CalcTool(), shield=shield, agent="trusted_agent")

    # max_amount for calculator is 1000.0
    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.run(a=10, b=20, amount=5000.0)

    assert exc_info.value.decision.decision == DecisionValue.BLOCK
    assert executed_count == 0
    assert wrapped.call_count == 0


def test_blocked_destination_violation():
    """Verifies destination allowlisting blocks unlisted hostnames."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    executed = False

    class SearchTool(MockCrewAIBaseTool):
        name: str = "search_tool"
        description: str = "Search tool"

        def _run(self, destination: str) -> str:
            nonlocal executed
            executed = True
            return "ok"

    wrapped = protect_crewai_tool(SearchTool(), shield=shield, agent="trusted_agent")

    with pytest.raises(ToolBlockedError) as exc_info:
        wrapped.run(destination="evil.untrusted.com")

    assert exc_info.value.decision.decision == DecisionValue.BLOCK
    assert not executed


def test_blocked_no_raise_mode():
    """Verifies raise_on_blocked=False returns ExecutionResult on block."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()

    class SearchTool(MockCrewAIBaseTool):
        name: str = "search_tool"
        description: str = "Search tool"

        def _run(self, destination: str) -> str:
            return "ok"

    wrapped = protect_crewai_tool(
        SearchTool(),
        shield=shield,
        agent="restricted_agent",
        raise_on_blocked=False,
    )

    result = wrapped.run(destination="api.search.internal")
    assert isinstance(result, ExecutionResult)
    assert result.decision.decision == DecisionValue.BLOCK
    assert result.execution_status == ExecutionStatus.NOT_EXECUTED
    assert result.tool_result is None


# ============================================================================
# 5. REVIEW enforcement & Human-in-the-loop approval
# ============================================================================

def test_review_required_and_approval_flow():
    """Verifies that REVIEW decisions enqueue for human approval, prevent execution,
    and execute once approved with frozen arguments.
    """
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    invocations = []

    class TransferTool(MockCrewAIBaseTool):
        name: str = "transfer_funds"
        description: str = "Transfer money"

        def _run(self, to_account: str, amount: float) -> str:
            invocations.append((to_account, amount))
            return f"Transferred ${amount} to {to_account}"

    wrapped = protect_crewai_tool(
        TransferTool(),
        shield=shield,
        agent="trusted_agent",
        permissions=["finance:transfer"],
    )

    # Elevated amount triggers REVIEW via risk evaluation
    with pytest.raises(ToolReviewRequiredError) as exc_info:
        wrapped.run(to_account="ACC-999", amount=5000.0)

    assert exc_info.value.decision.decision == DecisionValue.REVIEW
    assert exc_info.value.review_id is not None
    review_id = exc_info.value.review_id
    assert len(invocations) == 0
    assert wrapped.call_count == 0

    # Verify review item in review queue
    pending = shield.get_review_queue()
    assert any(item["review_id"] == review_id for item in pending)

    # Approve review and execute with frozen arguments
    approved_res = shield.approve_review(review_id, approver="security_officer")
    assert approved_res is not None
    assert approved_res.execution_status == ExecutionStatus.EXECUTED
    assert approved_res.tool_result == "Transferred $5000.0 to ACC-999"
    assert len(invocations) == 1

    # Second approval attempt must fail closed (at-most-once initiation)
    exec_again = shield.approve_review(review_id, approver="security_officer")
    assert exec_again is None or exec_again.execution_status == ExecutionStatus.NOT_EXECUTED
    assert len(invocations) == 1


# ============================================================================
# 6. Tool execution errors and exception safety
# ============================================================================

def test_underlying_tool_exception_logged_and_reraised():
    """Verifies that errors inside the underlying tool are audited and re-raised without retry."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    attempts = 0

    class FailingTool(MockCrewAIBaseTool):
        name: str = "failing_tool"
        description: str = "Fails always"

        def _run(self) -> None:
            nonlocal attempts
            attempts += 1
            raise RuntimeError("Database connection timed out")

    wrapped = protect_crewai_tool(FailingTool(), shield=shield, agent="trusted_agent")

    with pytest.raises(RuntimeError) as exc_info:
        wrapped.run()

    assert "Database connection timed out" in str(exc_info.value)
    assert attempts == 1

    # Check audit record
    records = shield.audit_store.query(tool="failing_tool")
    error_recs = [r for r in records if r.execution_status in ("error", "timeout")]
    assert len(error_recs) == 1
    assert "Database connection timed out" in (error_recs[0].error or "")


# ============================================================================
# 7. Async execution support
# ============================================================================

@pytest.mark.anyio
async def test_async_tool_allowed_execution():
    """Verifies asynchronous execution of CrewAI tools via arun and _arun."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()
    executed_count = 0

    class AsyncFetcher(MockCrewAIBaseTool):
        name: str = "async_fetcher"
        description: str = "Fetch data asynchronously"

        async def _arun(self, query: str) -> str:
            nonlocal executed_count
            executed_count += 1
            await asyncio.sleep(0.01)
            return f"results for {query}"

    wrapped = protect_crewai_tool(AsyncFetcher(), shield=shield, agent="trusted_agent")

    res = await wrapped.arun(query="antigravity")
    assert res == "results for antigravity"
    assert executed_count == 1
    assert wrapped.call_count == 1


@pytest.mark.anyio
async def test_async_tool_blocked_execution():
    """Verifies asynchronous execution respects policy blocks."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()

    class AsyncFetcher(MockCrewAIBaseTool):
        name: str = "async_fetcher"
        description: str = "Fetch data asynchronously"

        async def _arun(self, query: str) -> str:
            return f"results for {query}"

    wrapped = protect_crewai_tool(AsyncFetcher(), shield=shield, agent="restricted_agent")

    with pytest.raises(ToolBlockedError):
        await wrapped.arun(query="antigravity")


# ============================================================================
# 8. Dynamic call context overrides
# ============================================================================

def test_dynamic_call_context_overrides():
    """Verifies per-call overrides via _agent, _permissions, and _correlation_id."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()

    class CalcTool(MockCrewAIBaseTool):
        name: str = "calculator"
        description: str = "Calculator"

        def _run(self, a: int, b: int) -> int:
            return a + b

    # Created with restricted_agent
    wrapped = protect_crewai_tool(CalcTool(), shield=shield, agent="restricted_agent")

    # Override to trusted_agent with custom correlation ID
    res = wrapped.run(a=2, b=3, _agent="trusted_agent", _correlation_id="corr-xyz")
    assert res == 5

    records = shield.audit_store.query(tool="calculator")
    latest = records[-1]
    assert latest.agent == "trusted_agent"
    assert latest.correlation_id == "corr-xyz"


# ============================================================================
# 9. Argument shape normalization
# ============================================================================

def test_argument_extraction_from_dict_and_single_arg():
    """Verifies argument extraction when passed as a dict or positional arg."""
    from agentshield.integrations.crewai import protect_crewai_tool

    shield = create_test_shield()

    class SingleInput(BaseModel):
        val: int = Field(...)

    class CustomTool(MockCrewAIBaseTool):
        name: str = "custom_tool"
        description: str = "Single input tool"
        args_schema: Type[BaseModel] = SingleInput

        def _run(self, val: int) -> int:
            return val * 2

    wrapped = protect_crewai_tool(CustomTool(), shield=shield, agent="trusted_agent")

    # Passed as dict
    assert wrapped.run({"val": 21}) == 42
    # Passed as single positional arg
    assert wrapped.run(21) == 42
