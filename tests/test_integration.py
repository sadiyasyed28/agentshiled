import pytest
from agentshield import Shield
from agentshield.models import DecisionValue

def test_integration_create_order_quantity_2():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 2})
    assert decision.allowed is True
    assert decision.decision == DecisionValue.ALLOW

def test_integration_create_order_quantity_10():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 10})
    assert decision.allowed is True
    assert decision.decision == DecisionValue.ALLOW

def test_integration_create_order_quantity_11():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 11})
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("max_quantity" in r for r in decision.reasons)

def test_integration_create_order_quantity_999():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 999})
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK

def test_integration_delete_database():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="delete_database")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("unknown_tool" in r for r in decision.reasons)

def test_integration_missing_agent():
    shield = Shield()
    decision = shield.authorize(agent="", tool="create_order")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("Malformed request" in r for r in decision.reasons)

def test_integration_unauthorized_tool():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="refund_order")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("denied_tool" in r for r in decision.reasons)
