import pytest
from agentshield.models import Action
from agentshield.policy.engine import PolicyEngine
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule

def setup_engine():
    config = PolicyConfiguration(
        agents={
            "shopping_agent": AgentConfig(
                name="shopping_agent",
                allowed_tools=["search_product", "get_product", "create_order"],
                denied_tools=["refund_order"]
            )
        },
        tools={
            "create_order": ToolRule(tool="create_order", max_quantity=10),
            "refund_order": ToolRule(tool="refund_order", max_amount=10000, required_permissions=["refund"])
        }
    )
    return PolicyEngine(config)

def test_allowed_tool():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="create_order", arguments={"quantity": 5})
    results = engine.evaluate(action)
    assert all(r.passed for r in results)

def test_denied_tool():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="refund_order")
    results = engine.evaluate(action)
    assert any(not r.passed and r.rule == "denied_tool" for r in results)

def test_unknown_tool():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="delete_database")
    results = engine.evaluate(action)
    assert any(not r.passed and r.rule == "unknown_tool" for r in results)

def test_allowed_quantity():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="create_order", arguments={"quantity": 9})
    results = engine.evaluate(action)
    assert all(r.passed for r in results)

def test_quantity_exactly_at_limit():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="create_order", arguments={"quantity": 10})
    results = engine.evaluate(action)
    assert all(r.passed for r in results)

def test_quantity_above_limit():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="create_order", arguments={"quantity": 11})
    results = engine.evaluate(action)
    assert any(not r.passed and r.rule == "max_quantity" for r in results)

def test_required_permission_present():
    engine = setup_engine()
    engine.config.agents["manager"] = AgentConfig(name="manager", allowed_tools=["refund_order"])
    action = Action(agent="manager", tool="refund_order", arguments={"amount": 500})
    results = engine.evaluate(action, permissions=["refund"])
    assert all(r.passed for r in results)

def test_required_permission_missing():
    engine = setup_engine()
    engine.config.agents["manager"] = AgentConfig(name="manager", allowed_tools=["refund_order"])
    action = Action(agent="manager", tool="refund_order", arguments={"amount": 500})
    results = engine.evaluate(action, permissions=[])
    assert any(not r.passed and r.rule == "required_permission" for r in results)

def test_allowed_agent():
    engine = setup_engine()
    action = Action(agent="shopping_agent", tool="search_product")
    results = engine.evaluate(action)
    assert any(r.passed and r.rule == "allowed_agent" for r in results)

def test_unknown_agent():
    engine = setup_engine()
    action = Action(agent="hacker_agent", tool="search_product")
    results = engine.evaluate(action)
    assert any(not r.passed and r.rule == "allowed_agent" for r in results)
