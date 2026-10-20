import pytest
from agentshield.models import Action, DecisionValue, RiskLevel
from agentshield.risk.engine import RiskEngine, LOW_MAX, MEDIUM_MAX, HIGH_MAX
from agentshield import Shield
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule
from agentshield.policy.engine import PolicyEngine

def test_risk_determinism():
    engine = RiskEngine()
    action = Action(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 15})
    res1 = engine.evaluate(action=action)
    res2 = engine.evaluate(action=action)
    assert res1.score == res2.score
    assert res1.severity == res2.severity
    assert res1.factors == res2.factors

def test_risk_score_range_and_threshold_boundaries():
    engine = RiskEngine()
    
    # Boundary points based on centralized thresholds
    assert engine.calculate_severity(0.0) == RiskLevel.LOW
    assert engine.calculate_severity(LOW_MAX) == RiskLevel.LOW
    assert engine.calculate_severity(LOW_MAX + 0.1) == RiskLevel.MEDIUM
    assert engine.calculate_severity(MEDIUM_MAX) == RiskLevel.MEDIUM
    assert engine.calculate_severity(MEDIUM_MAX + 0.1) == RiskLevel.HIGH
    assert engine.calculate_severity(HIGH_MAX) == RiskLevel.HIGH
    assert engine.calculate_severity(HIGH_MAX + 0.1) == RiskLevel.CRITICAL
    assert engine.calculate_severity(100.0) == RiskLevel.CRITICAL

def test_risk_factors_deduplication_and_explanation():
    engine = RiskEngine()
    # Action with financial tool and repeated indicators
    action = Action(agent="admin", tool="refund_order", arguments={"amount": 6000, "quantity": 60})
    result = engine.evaluate(action=action)
    
    # Factors should be unique and formatted with explanation
    factor_names = [f.split(":")[0].strip() for f in result.factors]
    assert len(factor_names) == len(set(factor_names))
    for factor in result.factors:
        assert ":" in factor
        name, explanation = factor.split(":", 1)
        assert len(explanation.strip()) > 0

def test_policy_denial_precedence_over_low_risk():
    """
    Policy denial must NEVER be overridden to ALLOW, even when risk is low/zero.
    """
    shield = Shield()
    # refund_order is explicitly denied for shopping_agent in default Shield policy
    decision = shield.authorize(agent="shopping_agent", tool="refund_order", arguments={"amount": 5})
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("denied_tool" in r for r in decision.reasons)

def test_policy_unknown_tool_precedence():
    shield = Shield()
    decision = shield.authorize(agent="shopping_agent", tool="delete_database")
    assert decision.allowed is False
    assert decision.decision == DecisionValue.BLOCK
    assert any("unknown_tool" in r for r in decision.reasons)

def test_risk_can_elevate_allow_to_review_or_block():
    """
    When policy permits a tool, high risk elevates decision to REVIEW or BLOCK.
    """
    # Configure custom shield policy that permits high-amount refunds for manager
    config = PolicyConfiguration(
        agents={
            "manager": AgentConfig(name="manager", allowed_tools=["refund_order"])
        },
        tools={
            "refund_order": ToolRule(tool="refund_order", max_amount=100000)
        }
    )
    custom_shield = Shield()
    custom_shield.policy_engine = PolicyEngine(config)
    
    # Financial impact (40) + elevated amount (30) = score 70 -> HIGH risk -> REVIEW
    decision_review = custom_shield.authorize(agent="manager", tool="refund_order", arguments={"amount": 2000})
    assert decision_review.decision == DecisionValue.REVIEW
    assert decision_review.allowed is False
    assert decision_review.severity == RiskLevel.HIGH
    assert decision_review.risk_score >= 60.0

def test_risk_destructive_tool_elevates_to_critical_block():
    config = PolicyConfiguration(
        agents={
            "ops_agent": AgentConfig(name="ops_agent", allowed_tools=["format_disk"])
        },
        tools={
            "format_disk": ToolRule(tool="format_disk")
        }
    )
    custom_shield = Shield()
    custom_shield.policy_engine = PolicyEngine(config)

    decision_block = custom_shield.authorize(agent="ops_agent", tool="format_disk", arguments={})
    assert decision_block.decision == DecisionValue.BLOCK
    assert decision_block.allowed is False
    assert decision_block.severity == RiskLevel.CRITICAL
    assert decision_block.risk_score >= 85.0
