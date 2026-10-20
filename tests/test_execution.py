import pytest
from agentshield import Shield, ExecutionStatus
from agentshield.models import DecisionValue

def test_valid_action_execution():
    shield = Shield()
    counter = {"count": 0}
    
    def fake_create_order(arguments):
        counter["count"] += 1
        return {"status": "executed"}
        
    shield.registry.register("create_order", fake_create_order)
    
    res = shield.execute(agent="shopping_agent", tool="create_order", arguments={"product": "shoes"})
    assert res.decision.allowed is True
    assert res.decision.decision == DecisionValue.ALLOW
    assert res.execution_status == ExecutionStatus.EXECUTED
    assert counter["count"] == 1
    assert res.tool_result == {"status": "executed"}

def test_unknown_tool_no_execution():
    shield = Shield()
    counter = {"count": 0}
    
    # Tool not registered, unknown to policy
    res = shield.execute(agent="shopping_agent", tool="unknown_tool", arguments={})
    assert res.decision.allowed is False
    assert res.decision.decision == DecisionValue.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res.tool_result is None

def test_malformed_action_no_execution():
    shield = Shield()
    counter = {"count": 0}
    
    def fake_create_order(arguments):
        counter["count"] += 1
        return {"status": "executed"}
        
    shield.registry.register("create_order", fake_create_order)
    
    # Missing agent makes it malformed -> BLOCK, counter 0
    res = shield.execute(agent="", tool="create_order", arguments={"product": "shoes"})
    assert res.decision.allowed is False
    assert res.decision.decision == DecisionValue.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res.tool_result is None

    # Invalid arguments type -> BLOCK, counter 0
    res_args = shield.execute(agent="shopping_agent", tool="create_order", arguments=["not_a_dict"])
    assert res_args.decision.allowed is False
    assert res_args.decision.decision == DecisionValue.BLOCK
    assert res_args.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res_args.tool_result is None

def test_unauthorized_action_no_execution():
    shield = Shield()
    counter = {"count": 0}
    
    def fake_create_order(arguments):
        counter["count"] += 1
        return {"status": "executed"}
        
    shield.registry.register("create_order", fake_create_order)
    
    # evil_agent is unauthorized -> BLOCK, counter 0
    res = shield.execute(agent="evil_agent", tool="create_order", arguments={"product": "shoes"})
    assert res.decision.allowed is False
    assert res.decision.decision == DecisionValue.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res.tool_result is None

def test_registered_tool_alone_does_not_grant_permission():
    shield = Shield()
    counter = {"count": 0}

    def fake_delete_db(arguments):
        counter["count"] += 1
        return {"deleted": True}

    # Registered in ToolRegistry, but NOT permitted by policy
    shield.registry.register("delete_database", fake_delete_db)
    assert shield.registry.has_tool("delete_database") is True

    res = shield.execute(agent="shopping_agent", tool="delete_database", arguments={})
    assert res.decision.allowed is False
    assert res.decision.decision == DecisionValue.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res.tool_result is None

def test_policy_blocked_tool_no_execution():
    shield = Shield()
    counter = {"count": 0}

    def fake_refund(arguments):
        counter["count"] += 1
        return {"refunded": True}

    shield.registry.register("refund_order", fake_refund)

    # refund_order is explicitly denied for shopping_agent -> BLOCK, counter 0
    res = shield.execute(agent="shopping_agent", tool="refund_order", arguments={"amount": 50})
    assert res.decision.allowed is False
    assert res.decision.decision == DecisionValue.BLOCK
    assert res.execution_status == ExecutionStatus.NOT_EXECUTED
    assert counter["count"] == 0
    assert res.tool_result is None

def test_tool_execution_error_status():
    shield = Shield()

    def failing_tool(arguments):
        raise RuntimeError("Tool failed unexpectedly")

    shield.registry.register("create_order", failing_tool)

    res = shield.execute(agent="shopping_agent", tool="create_order", arguments={"product": "shoes"})
    assert res.decision.allowed is True
    assert res.decision.decision == DecisionValue.ALLOW
    assert res.execution_status == ExecutionStatus.ERROR
    assert "Tool failed unexpectedly" in (res.error or "")
    assert res.tool_result is None

def test_valid_action_executed_twice():
    shield = Shield()
    counter = {"count": 0}
    
    def fake_create_order(arguments):
        counter["count"] += 1
        return {"status": "executed"}
        
    shield.registry.register("create_order", fake_create_order)
    
    res1 = shield.execute(agent="shopping_agent", tool="create_order", arguments={"product": "shoes"})
    assert res1.execution_status == ExecutionStatus.EXECUTED
    assert counter["count"] == 1
    
    res2 = shield.execute(agent="shopping_agent", tool="create_order", arguments={"product": "shoes"})
    assert res2.execution_status == ExecutionStatus.EXECUTED
    assert counter["count"] == 2
