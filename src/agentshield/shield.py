from typing import Any, Optional, Dict, List
from agentshield.models import Action, Decision, DecisionValue, RiskLevel
from agentshield.tools.registry import ToolRegistry
from agentshield.policy.engine import PolicyEngine
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule

from enum import Enum

class ExecutionStatus(Enum):
    EXECUTED = "executed"
    NOT_EXECUTED = "not_executed"
    ERROR = "error"

class ExecutionResult:
    def __init__(
        self,
        decision: Decision,
        execution_status: ExecutionStatus,
        tool_result: Any = None,
        error: Optional[str] = None
    ):
        self.decision = decision
        self.execution_status = execution_status
        self.tool_result = tool_result
        self.error = error

from agentshield.risk.engine import RiskEngine

class Shield:
    def __init__(self, risk_engine: Optional[RiskEngine] = None):
        self.registry = ToolRegistry()
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
        self.policy_engine = PolicyEngine(config)
        self.risk_engine = risk_engine or RiskEngine()

    def check(self, user_input: str) -> Decision:
        risk_result = self.risk_engine.evaluate(user_input=user_input)
        if "rm -rf" in user_input or "drop table" in user_input.lower() or risk_result.severity == RiskLevel.CRITICAL:
            reasons = ["Input contains forbidden patterns"]
            if risk_result.factors:
                reasons.extend(risk_result.factors)
            return self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent="unknown",
                tool="unknown"
            )
        
        reasons = ["Input looks safe"]
        if risk_result.factors:
            reasons.extend(risk_result.factors)

        decision_val = DecisionValue.ALLOW
        if risk_result.severity in (RiskLevel.HIGH, RiskLevel.MEDIUM) and risk_result.score > 50:
            decision_val = DecisionValue.REVIEW

        return self._build_decision(
            allowed=(decision_val == DecisionValue.ALLOW),
            decision=decision_val,
            reasons=reasons,
            risk_score=risk_result.score,
            severity=risk_result.severity,
            agent="unknown",
            tool="unknown"
        )

    def authorize(self, agent: str, tool: str, arguments: Optional[Dict[str, Any]] = None, permissions: Optional[List[str]] = None) -> Decision:
        if arguments is None:
            arguments = {}
        if permissions is None:
            permissions = []
            
        try:
            action = Action(agent=agent, tool=tool, arguments=arguments)
        except (ValueError, TypeError) as e:
            return self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=[f"Malformed request: {str(e)}"],
                risk_score=80.0,
                severity=RiskLevel.HIGH,
                agent=agent if isinstance(agent, str) and agent else "unknown",
                tool=tool if isinstance(tool, str) and tool else "unknown"
            )

        # 1. Deterministic Policy Evaluation (fails closed)
        policy_results = self.policy_engine.evaluate(action, permissions)
        failed_policies = [p for p in policy_results if not p.passed]

        # 2. Risk Evaluation
        risk_result = self.risk_engine.evaluate(action=action, permissions=permissions)

        # Policy failure ALWAYS takes absolute precedence -> BLOCK (risk never overrides policy denial)
        if failed_policies:
            reasons = [f"Policy failed: {p.rule} - {p.reason}" for p in failed_policies]
            if risk_result.factors:
                reasons.extend(risk_result.factors)
            return self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=max(risk_result.score, 80.0),
                severity=RiskLevel.HIGH if risk_result.severity in (RiskLevel.LOW, RiskLevel.MEDIUM) else risk_result.severity,
                agent=action.agent,
                tool=action.tool
            )

        # 3. Policy passed: risk can elevate ALLOW to REVIEW or BLOCK
        reasons = ["Action authorized"]
        if risk_result.factors:
            reasons.extend(risk_result.factors)

        if risk_result.severity == RiskLevel.CRITICAL:
            return self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent=action.agent,
                tool=action.tool
            )
        elif risk_result.severity == RiskLevel.HIGH:
            return self._build_decision(
                allowed=False,
                decision=DecisionValue.REVIEW,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent=action.agent,
                tool=action.tool
            )

        return self._build_decision(
            allowed=True,
            decision=DecisionValue.ALLOW,
            reasons=reasons,
            risk_score=risk_result.score,
            severity=risk_result.severity,
            agent=action.agent,
            tool=action.tool
        )
        
    def execute(self, agent: str, tool: str, arguments: Optional[Dict[str, Any]] = None, permissions: Optional[List[str]] = None) -> ExecutionResult:
        decision = self.authorize(agent, tool, arguments, permissions)
        if decision.decision != DecisionValue.ALLOW or not decision.allowed:
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None)
            
        registered_tool = self.registry.get_tool(tool)
        if not registered_tool:
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None, error=f"Tool {tool} not found in registry")

        args = arguments or {}
        try:
            result = registered_tool.callable_func(args)
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=result)
        except Exception as e:
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.ERROR, tool_result=None, error=str(e))

    def _build_decision(self, allowed: bool, decision: DecisionValue, reasons: list[str],
                        risk_score: float, severity: RiskLevel, agent: str, tool: str) -> Decision:
        return Decision(
            allowed=allowed,
            decision=decision,
            reasons=reasons,
            risk_score=risk_score,
            severity=severity,
            agent=agent,
            tool=tool
        )
