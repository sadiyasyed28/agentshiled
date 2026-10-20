from agentshield.models import Action, PolicyResult
from agentshield.policy.rules import PolicyConfiguration

class PolicyEngine:
    def __init__(self, config: PolicyConfiguration = None):
        self.config = config or PolicyConfiguration()

    @property
    def known_tools(self) -> set[str]:
        tools = set(self.config.tools.keys())
        for agent in self.config.agents.values():
            tools.update(agent.allowed_tools)
            tools.update(agent.denied_tools)
        return tools

    def evaluate(self, action: Action, permissions: list[str] = None) -> list[PolicyResult]:
        results = []
        permissions = permissions or []

        if action.tool not in self.known_tools:
            results.append(PolicyResult(passed=False, rule="unknown_tool", reason=f"Unknown tool: {action.tool}"))
            return results

        # 1. Agent existence and allowed tools
        agent_config = self.config.agents.get(action.agent)
        if not agent_config:
            results.append(PolicyResult(passed=False, rule="allowed_agent", reason=f"Unknown agent: {action.agent}"))
            return results
        else:
            results.append(PolicyResult(passed=True, rule="allowed_agent", reason="Agent is configured"))

        if action.tool in agent_config.denied_tools:
            results.append(PolicyResult(passed=False, rule="denied_tool", reason=f"Tool {action.tool} is explicitly denied for agent {action.agent}"))
        elif agent_config.allowed_tools and action.tool not in agent_config.allowed_tools:
            results.append(PolicyResult(passed=False, rule="allowed_tool", reason=f"Tool {action.tool} is not allowed for agent {action.agent}"))
        else:
            results.append(PolicyResult(passed=True, rule="allowed_tool", reason="Tool is permitted for agent"))

        # 2. Tool-specific rules
        tool_rule = self.config.tools.get(action.tool)
        if tool_rule:
            for req_perm in tool_rule.required_permissions:
                if req_perm not in permissions:
                    results.append(PolicyResult(passed=False, rule="required_permission", reason=f"Missing required permission: {req_perm}"))
                else:
                    results.append(PolicyResult(passed=True, rule="required_permission", reason=f"Has permission: {req_perm}"))
            
            quantity = action.arguments.get("quantity")
            if quantity is not None:
                if isinstance(quantity, (int, float)) and quantity > tool_rule.max_quantity:
                    results.append(PolicyResult(passed=False, rule="max_quantity", reason=f"Quantity {quantity} exceeds maximum of {tool_rule.max_quantity}"))
                else:
                    results.append(PolicyResult(passed=True, rule="max_quantity", reason="Quantity within limits"))

            amount = action.arguments.get("amount")
            if amount is not None:
                if isinstance(amount, (int, float)) and amount > tool_rule.max_amount:
                    results.append(PolicyResult(passed=False, rule="max_amount", reason=f"Amount {amount} exceeds maximum of {tool_rule.max_amount}"))
                else:
                    results.append(PolicyResult(passed=True, rule="max_amount", reason="Amount within limits"))

        return results
