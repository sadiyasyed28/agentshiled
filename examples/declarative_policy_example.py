"""
AgentShield Standalone SDK Example — Declarative Policy Configuration

Demonstrates how to define, validate, and load deterministic security policies
using dictionaries or YAML for tool-using AI agents.
"""

from agentshield import (
    Shield,
    PolicyConfiguration,
    PolicyValidationError,
)


def main():
    print("=== AgentShield Declarative Policy Example ===\n")

    # 1. Define a declarative security policy using a Python dictionary
    policy_spec = {
        "version": "1",
        "agents": {
            "customer_support_agent": {
                "name": "customer_support_agent",
                "allowed_tools": ["lookup_order", "check_refund_eligibility"],
                "denied_tools": ["process_refund", "execute_sql"],
                "allowed_destinations": ["api.internal.store"],
            },
            "finance_manager_agent": {
                "name": "finance_manager_agent",
                "allowed_tools": ["process_refund", "lookup_order"],
                "allowed_destinations": ["api.internal.store", "payments.processor.net"],
            },
        },
        "tools": {
            "lookup_order": {
                "max_quantity": "inf",
                "allowed_destinations": ["api.internal.store"],
                "argument_schema": {
                    "order_id": "str",
                },
            },
            "check_refund_eligibility": {
                "max_amount": 500.0,
                "argument_schema": {
                    "order_id": "str",
                    "reason": "str",
                },
            },
            "process_refund": {
                "max_amount": 1000.0,
                "required_permissions": ["finance:refund"],
                "allowed_destinations": ["payments.processor.net"],
                "argument_schema": {
                    "order_id": "str",
                    "amount": "float",
                },
            },
            "execute_sql": {
                "max_amount": 0,
            },
        },
    }

    # Validate and parse the policy into a PolicyConfiguration object
    policy = PolicyConfiguration.from_dict(policy_spec)
    print(f"Loaded policy version hash: {policy.compute_version_hash()}\n")

    # 2. Instantiate Shield with the declarative policy
    shield = Shield(policy=policy)

    # Register tool implementations
    shield.registry.register(
        "lookup_order",
        lambda args: {"order_id": args["order_id"], "status": "shipped", "items": ["Laptop", "Mouse"]}
    )
    shield.registry.register(
        "process_refund",
        lambda args: {"refund_id": "ref_9921", "amount": args["amount"], "status": "processed"}
    )

    # Scenario 1: Support agent performs legitimate order lookup -> ALLOW
    print("--- Scenario 1: Support agent performs legitimate lookup ---")
    res1 = shield.execute(
        agent="customer_support_agent",
        tool="lookup_order",
        arguments={"order_id": "ord_1001", "destination": "api.internal.store"},
    )
    print(f"Decision: {res1.decision.decision.value} (Allowed: {res1.decision.allowed})")
    print(f"Result:   {res1.tool_result}\n")

    # Scenario 2: Support agent attempts unauthorized refund -> BLOCK (denied_tool)
    print("--- Scenario 2: Support agent attempts unauthorized refund ---")
    res2 = shield.execute(
        agent="customer_support_agent",
        tool="process_refund",
        arguments={"order_id": "ord_1001", "amount": 150.0},
    )
    print(f"Decision: {res2.decision.decision.value} (Allowed: {res2.decision.allowed})")
    print(f"Reasons:  {res2.decision.reasons}")
    print(f"Executed: {res2.execution_status.value} (Tool was NOT invoked)\n")

    # Scenario 3: Finance agent attempts refund exceeding policy limit ($1000) -> BLOCK
    print("--- Scenario 3: Finance agent attempts refund over policy limit ---")
    res3 = shield.execute(
        agent="finance_manager_agent",
        tool="process_refund",
        arguments={"order_id": "ord_1001", "amount": 4500.0, "destination": "payments.processor.net"},
        permissions=["finance:refund"],
    )
    print(f"Decision: {res3.decision.decision.value} (Allowed: {res3.decision.allowed})")
    print(f"Reasons:  {res3.decision.reasons}\n")

    # Scenario 4: Unknown agent attempts action -> BLOCK (fail-closed)
    print("--- Scenario 4: Unknown agent attempts tool call ---")
    res4 = shield.execute(
        agent="untrusted_crawler",
        tool="lookup_order",
        arguments={"order_id": "ord_1001"},
    )
    print(f"Decision: {res4.decision.decision.value} (Allowed: {res4.decision.allowed})")
    print(f"Reasons:  {res4.decision.reasons}\n")

    # Scenario 5: Policy validation catch for malformed configurations
    print("--- Scenario 5: Detecting contradictory policy specifications ---")
    try:
        PolicyConfiguration.from_dict({
            "agents": {
                "bot": {
                    "allowed_tools": ["write_data"],
                    "denied_tools": ["write_data"],  # Contradictory!
                }
            }
        })
    except PolicyValidationError as err:
        print(f"Caught expected validation error: {err}\n")

    print("=== Example completed successfully ===")


if __name__ == "__main__":
    main()
