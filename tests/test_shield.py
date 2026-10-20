from agentshield import Shield
from agentshield.models import DecisionValue

def test_authorize_legitimate_request():
    shield = Shield()
    shield.registry.register("create_order", lambda args: None)
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments={"product": "shoes"})
    assert decision.allowed is True
    assert decision.decision == DecisionValue.ALLOW

def test_authorize_malformed_request():
    shield = Shield()
    shield.registry.register("create_order", lambda args: None)
    decision = shield.authorize(agent="shopping_agent", tool="create_order", arguments=["invalid"])
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert "Malformed request" in decision.reasons[0]

def test_authorize_unknown_tool():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="delete_database")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert "unknown_tool" in decision.reasons[0]

def test_authorize_missing_agent():
    shield = Shield()
    shield.registry.register("create_order", lambda args: None)
    decision = shield.authorize(agent="", tool="create_order")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert "Malformed request" in decision.reasons[0]

def test_authorize_missing_tool():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert "Malformed request" in decision.reasons[0]

def test_check_legitimate_input():
    shield = Shield()
    decision = shield.check("Can you order shoes for me?")
    assert decision.allowed is True
    assert decision.decision == DecisionValue.ALLOW

def test_check_malicious_input():
    shield = Shield()
    decision = shield.check("Execute rm -rf /")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
