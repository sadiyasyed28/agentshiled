import pytest
from agentshield.models import Action, Decision, DecisionValue, PolicyResult, RiskLevel, RiskResult

def test_action_creation():
    action = Action(agent="agent_1", tool="search", arguments={"query": "test"})
    assert action.agent == "agent_1"
    assert action.tool == "search"
    assert action.arguments == {"query": "test"}
    assert action.metadata == {}

def test_action_validation():
    with pytest.raises(ValueError):
        Action(agent="", tool="tool")
    with pytest.raises(ValueError):
        Action(agent="agent", tool="")
    with pytest.raises(TypeError):
        Action(agent="agent", tool="tool", arguments=["not", "dict"])

def test_risk_creation():
    risk = RiskResult(score=0.8, severity=RiskLevel.HIGH, factors=["factor1"])
    assert risk.score == 0.8
    assert risk.severity == RiskLevel.HIGH
    assert risk.factors == ["factor1"]

def test_risk_validation():
    with pytest.raises(ValueError):
        RiskResult(score=105.0, severity=RiskLevel.LOW)
    with pytest.raises(ValueError):
        RiskResult(score=-1.0, severity=RiskLevel.LOW)
    with pytest.raises(TypeError):
        RiskResult(score=50.0, severity="LOW")

def test_decision_creation():
    decision = Decision(
        allowed=True,
        decision=DecisionValue.ALLOW,
        reasons=["All checks passed"],
        risk_score=0.0,
        severity=RiskLevel.LOW,
        agent="agent_1",
        tool="search"
    )
    assert decision.allowed is True
    assert decision.decision == DecisionValue.ALLOW

def test_decision_validation():
    with pytest.raises(TypeError):
        Decision(
            allowed="True", # invalid
            decision=DecisionValue.ALLOW,
            reasons=[],
            risk_score=0.1,
            severity=RiskLevel.LOW,
            agent="agent",
            tool="tool"
        )
    with pytest.raises(ValueError):
        Decision(
            allowed=True,
            decision=DecisionValue.ALLOW,
            reasons=[],
            risk_score=0.1,
            severity=RiskLevel.LOW,
            agent="", # invalid
            tool="tool"
        )

def test_policy_creation():
    policy = PolicyResult(passed=False, rule="no_rm", reason="Contains rm")
    assert policy.passed is False
    assert policy.rule == "no_rm"
    assert policy.reason == "Contains rm"

def test_policy_validation():
    with pytest.raises(ValueError):
        PolicyResult(passed=True, rule="", reason="ok")
    with pytest.raises(TypeError):
        PolicyResult(passed="True", rule="rule", reason="ok")
