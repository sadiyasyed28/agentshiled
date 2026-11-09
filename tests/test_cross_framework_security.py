"""Shared Cross-Framework Security Test Matrix.

Verifies equivalent security invariants across all four AgentShield execution paths:
1. Core SDK (`shield.execute()`)
2. Decorator (`@shield.protect_tool`)
3. LangChain adapter (`protect_langchain_tool()`)
4. CrewAI adapter (`protect_crewai_tool()`)
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
import types
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
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
    SQLiteAuditStore,
)
from agentshield.models import DecisionValue
from langchain_core.tools import tool as lc_tool

# Mock CrewAI BaseTool if crewai is not installed (e.g. Python >= 3.14)
class MockCrewAIBaseTool(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")
    name: str = Field(...)
    description: str = Field(...)
    args_schema: Optional[Type[BaseModel]] = Field(default=None)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


@pytest.fixture(autouse=True)
def inject_crewai_mock(monkeypatch):
    mock_crewai_tools = types.ModuleType("crewai.tools")
    mock_crewai_tools.BaseTool = MockCrewAIBaseTool
    mock_crewai = types.ModuleType("crewai")
    mock_crewai.tools = mock_crewai_tools
    mock_crewai.BaseTool = MockCrewAIBaseTool

    monkeypatch.setitem(sys.modules, "crewai", mock_crewai)
    monkeypatch.setitem(sys.modules, "crewai.tools", mock_crewai_tools)
    sys.modules.pop("agentshield.integrations.crewai", None)
    yield


def create_security_test_shield():
    audit_store = SQLiteAuditStore(":memory:")
    policy = PolicyConfiguration(
        agents={
            "trusted_agent": AgentConfig(
                name="trusted_agent",
                allowed_tools=["calculator", "transfer_funds", "search_tool", "failing_tool"],
            ),
            "restricted_agent": AgentConfig(
                name="restricted_agent",
                allowed_tools=["calculator"],
                denied_tools=["transfer_funds"],
            ),
        },
        tools={
            "calculator": ToolRule(
                tool="calculator",
                max_amount=1000.0,
            ),
            "transfer_funds": ToolRule(
                tool="transfer_funds",
                max_amount=100000.0,
                required_permissions=["finance:transfer"],
            ),
            "search_tool": ToolRule(
                tool="search_tool",
                allowed_destinations=["api.internal.corp"],
            ),
            "failing_tool": ToolRule(
                tool="failing_tool",
            ),
        },
    )
    return Shield(audit_store=audit_store, policy=policy, review_ttl_seconds=300.0)


# ============================================================================
# Helpers to setup tools across all 4 execution paths
# ============================================================================

def setup_path_runner(path: str, shield: Shield, tool_name: str, target_callable: Callable, **kwargs):
    """Returns an invoker callable `run_fn(**kwargs)` for the requested framework path."""
    if path == "core":
        shield.registry.register(name=tool_name, callable_func=target_callable)
        def _core_runner(**call_args):
            agent = call_args.pop("_agent", "trusted_agent")
            perms = call_args.pop("_permissions", ["finance:transfer"] if tool_name == "transfer_funds" else [])
            res = shield.execute(agent=agent, tool=tool_name, arguments=call_args, permissions=perms)
            if res.execution_status == ExecutionStatus.ERROR and res.error:
                raise RuntimeError(res.error)
            if res.decision.decision == DecisionValue.BLOCK:
                raise ToolBlockedError("; ".join(res.decision.reasons), decision=res.decision, tool_name=tool_name, agent=agent)
            if res.decision.decision == DecisionValue.REVIEW:
                raise ToolReviewRequiredError("Review required", decision=res.decision, tool_name=tool_name, agent=agent, review_id=res.decision.review_id)
            return res.tool_result
        return _core_runner

    elif path == "decorator":
        decorated = shield.protect_tool(
            target_callable,
            name=tool_name,
            agent="trusted_agent",
            permissions=["finance:transfer"] if tool_name == "transfer_funds" else [],
            **kwargs,
        )
        return decorated

    elif path == "langchain":
        doc = target_callable.__doc__ or "LangChain tool doc"
        wrapped = shield.protect_langchain_tool(
            target_callable,
            name=tool_name,
            description=doc,
            agent="trusted_agent",
            permissions=["finance:transfer"] if tool_name == "transfer_funds" else [],
            **kwargs,
        )
        def _lc_runner(**call_args):
            return wrapped.invoke(call_args)
        _lc_runner.tool_instance = wrapped
        return _lc_runner

    elif path == "crewai":
        class CustomCrewTool(MockCrewAIBaseTool):
            name: str = tool_name
            description: str = "CrewAI tool description"

            def _run(self, *a, **kw):
                if a and not kw:
                    if len(a) == 1 and isinstance(a[0], dict):
                        return target_callable(**a[0])
                    return target_callable(*a)
                return target_callable(**kw)

        tool_inst = CustomCrewTool()
        wrapped = shield.protect_crewai_tool(
            tool_inst,
            agent="trusted_agent",
            permissions=["finance:transfer"] if tool_name == "transfer_funds" else [],
            **kwargs,
        )
        def _crew_runner(**call_args):
            return wrapped.run(**call_args)
        _crew_runner.tool_instance = wrapped
        return _crew_runner

    raise ValueError(f"Unknown path {path}")


FRAMEWORK_PATHS = ["core", "decorator", "langchain", "crewai"]


# ============================================================================
# 1. ALLOW: Authorization before execution, executes exactly once, audited
# ============================================================================

@pytest.mark.parametrize("path", FRAMEWORK_PATHS)
def test_cross_framework_allow_exact_once(path):
    shield = create_security_test_shield()
    call_counts = []

    def calc(a: int, b: int) -> int:
        """Add numbers."""
        call_counts.append((a, b))
        return a + b

    runner = setup_path_runner(path, shield, "calculator", calc)
    res = runner(a=10, b=20)
    assert res == 30
    assert len(call_counts) == 1
    assert call_counts[0] == (10, 20)

    # Verify audit record
    records = shield.audit_store.query(tool="calculator")
    assert len(records) >= 1
    last_rec = records[-1]
    assert last_rec.decision == "ALLOW"
    assert last_rec.execution_status == "executed"
    assert last_rec.agent == "trusted_agent"


# ============================================================================
# 2. BLOCK: Original callable never executes, recorded correctly
# ============================================================================

@pytest.mark.parametrize("path", FRAMEWORK_PATHS)
def test_cross_framework_block_never_executes(path):
    shield = create_security_test_shield()
    call_counts = []

    def calc(a: int, b: int) -> int:
        call_counts.append((a, b))
        return a + b

    runner = setup_path_runner(path, shield, "calculator", calc)

    # Calling with unauthorized agent
    with pytest.raises(ToolBlockedError) as exc_info:
        runner(a=10, b=20, _agent="unauthorized_agent")

    assert len(call_counts) == 0
    assert exc_info.value.decision.decision == DecisionValue.BLOCK

    records = shield.audit_store.query(tool="calculator")
    assert any(r.execution_status == "not_executed" and r.decision == "BLOCK" for r in records)


# ============================================================================
# 3. REVIEW: Never executes before approval, executes with frozen arguments
# ============================================================================

@pytest.mark.parametrize("path", FRAMEWORK_PATHS)
def test_cross_framework_review_human_approval_resume(path):
    shield = create_security_test_shield()
    invocations = []

    def transfer_funds(to_account: str, amount: float) -> str:
        invocations.append((to_account, amount))
        return f"Transferred ${amount} to {to_account}"

    runner = setup_path_runner(path, shield, "transfer_funds", transfer_funds)

    # High amount triggers REVIEW
    with pytest.raises(ToolReviewRequiredError) as exc_info:
        runner(to_account="ACC-555", amount=5000.0)

    assert len(invocations) == 0
    assert exc_info.value.decision.decision == DecisionValue.REVIEW
    review_id = exc_info.value.review_id
    assert review_id is not None

    # Review is in pending queue
    pending = shield.get_review_queue()
    assert any(item["review_id"] == review_id for item in pending)

    # Approve review
    approval_res = shield.approve_review(review_id, approver="lead_auditor")
    assert approval_res is not None
    assert approval_res.execution_status == ExecutionStatus.EXECUTED
    assert approval_res.tool_result == "Transferred $5000.0 to ACC-555"
    assert len(invocations) == 1
    assert invocations[0] == ("ACC-555", 5000.0)

    # Replay attempt must fail closed
    exec_again = shield.approve_review(review_id, approver="second_auditor")
    assert exec_again is None or exec_again.execution_status == ExecutionStatus.NOT_EXECUTED
    assert len(invocations) == 1


# ============================================================================
# 4. Direct Escape Paths: __wrapped__ and wrapped_tool forbidden
# ============================================================================

def test_decorator_escape_path_forbidden():
    shield = create_security_test_shield()

    @shield.protect_tool(agent="trusted_agent")
    def secret_function():
        return "raw_execution"

    # __wrapped__ was removed to prevent direct execution bypass
    assert not hasattr(secret_function, "__wrapped__")
    with pytest.raises(AttributeError):
        _ = secret_function.__wrapped__


def test_langchain_escape_path_forbidden():
    shield = create_security_test_shield()

    @lc_tool
    def secret_cmd():
        """Secret tool."""
        return "raw_execution"

    safe = shield.protect_langchain_tool(secret_cmd, agent="trusted_agent")
    with pytest.raises(PermissionError) as exc_info:
        _ = safe.wrapped_tool
    assert "forbidden" in str(exc_info.value).lower()


def test_crewai_escape_path_forbidden():
    shield = create_security_test_shield()

    class SecretCrewTool(MockCrewAIBaseTool):
        name: str = "secret_crew"
        description: str = "Secret"

        def _run(self):
            return "raw_execution"

    safe = shield.protect_crewai_tool(SecretCrewTool(), agent="trusted_agent")
    with pytest.raises(PermissionError) as exc_info:
        _ = safe.wrapped_tool
    assert "forbidden" in str(exc_info.value).lower()


# ============================================================================
# 5. Argument Mutation Immunity: Caller cannot alter authorized arguments
# ============================================================================

def test_decorator_argument_mutation_immunity():
    shield = create_security_test_shield()
    from agentshield.policy.rules import ToolRule
    shield.policy_engine.config.agents["trusted_agent"].allowed_tools.append("process_order")
    shield.policy_engine.config.tools["process_order"] = ToolRule(tool="process_order")
    executed_args = []

    @shield.protect_tool(agent="trusted_agent")
    def process_order(payload: dict):
        executed_args.append(dict(payload))
        return "ok"

    data = {"item": "widget", "qty": 10}
    # Execute through wrapper
    res = process_order(data)
    assert res == "ok"
    assert executed_args[0] == {"item": "widget", "qty": 10}

    # Mutating original caller dict after call cannot alter what executed or audit
    data["qty"] = 999999
    records = shield.audit_store.query(tool="process_order")
    assert len(records) >= 1
    # Arguments in audit record are preserved as frozen original
    assert records[-1].arguments["payload"]["qty"] == 10


# ============================================================================
# 6. Concurrency: Atomic claims prevent race conditions in reviews
# ============================================================================

def test_concurrent_approval_requests_execute_at_most_once():
    shield = create_security_test_shield()
    invocations = []

    def transfer_funds(to_account: str, amount: float) -> str:
        invocations.append((to_account, amount))
        time.sleep(0.02)
        return f"transferred_{amount}"

    shield.registry.register("transfer_funds", transfer_funds)
    dec = shield.authorize("trusted_agent", "transfer_funds", {"to_account": "ACC-1", "amount": 5000.0}, permissions=["finance:transfer"])
    review_id = dec.review_id

    results = []
    def worker(idx):
        res = shield.approve_review(review_id, approver=f"admin_{idx}")
        results.append(res)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()

    executed = [r for r in results if r is not None and r.execution_status == ExecutionStatus.EXECUTED]
    assert len(executed) == 1
    assert len(invocations) == 1


# ============================================================================
# 7. Containment: Paused agents cannot execute via review approval
# ============================================================================

def test_paused_agent_review_approval_fails_closed():
    shield = create_security_test_shield()
    invocations = []

    def transfer_funds(to_account: str, amount: float) -> str:
        invocations.append((to_account, amount))
        return "done"

    shield.registry.register("transfer_funds", transfer_funds)
    dec = shield.authorize("trusted_agent", "transfer_funds", {"to_account": "ACC-9", "amount": 5000.0}, permissions=["finance:transfer"])
    review_id = dec.review_id

    # Pause agent during incident response
    shield.pause_agent("trusted_agent", actor="incident_lead")
    assert shield.is_agent_paused("trusted_agent") is True

    # Attempting to approve review for paused agent must fail closed
    res = shield.approve_review(review_id, approver="supervisor")
    assert res is not None
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert res.decision.decision == DecisionValue.BLOCK
    assert len(invocations) == 0, "Paused agent must NEVER execute tools via approval"


# ============================================================================
# 8. Policy Invariant: Denied policy changes before approval fail closed
# ============================================================================

def test_policy_denial_change_before_approval_fails_closed():
    shield = create_security_test_shield()
    invocations = []

    def transfer_funds(to_account: str, amount: float) -> str:
        invocations.append((to_account, amount))
        return "done"

    shield.registry.register("transfer_funds", transfer_funds)
    dec = shield.authorize("trusted_agent", "transfer_funds", {"to_account": "ACC-9", "amount": 5000.0}, permissions=["finance:transfer"])
    review_id = dec.review_id

    # Policy update: transfer_funds is now explicitly denied for trusted_agent
    shield.policy_engine.config.agents["trusted_agent"].denied_tools = ["transfer_funds"]

    # Approval must re-validate deterministic policy and fail closed
    res = shield.approve_review(review_id, approver="supervisor")
    assert res is not None
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert res.decision.decision == DecisionValue.BLOCK
    assert len(invocations) == 0, "Deterministic policy denial must take precedence over approval"


# ============================================================================
# 9. Whitespace-only agent identity fails closed
# ============================================================================

def test_whitespace_agent_identity_fails_closed():
    shield = create_security_test_shield()
    for bad_agent in ["", "   ", "\t\n", None]:
        dec = shield.authorize(agent=bad_agent, tool="calculator", arguments={"a": 1, "b": 2})
        assert dec.decision == DecisionValue.BLOCK
        assert any("agent must be a non-empty string" in r.lower() for r in dec.reasons)


# ============================================================================
# 10. Exception Safety: Underlying tool errors audited without accidental retry
# ============================================================================

@pytest.mark.parametrize("path", FRAMEWORK_PATHS)
def test_cross_framework_exception_audited_and_no_retry(path):
    shield = create_security_test_shield()
    attempts = 0

    def failing_tool():
        """Failing tool doc."""
        nonlocal attempts
        attempts += 1
        raise ValueError("Database connection lost")

    runner = setup_path_runner(path, shield, "failing_tool", failing_tool)

    with pytest.raises(Exception) as exc_info:
        runner()

    assert "Database connection lost" in str(exc_info.value)
    assert attempts == 1

    records = shield.audit_store.query(tool="failing_tool")
    assert any(r.execution_status in ("error", "timeout") for r in records)
