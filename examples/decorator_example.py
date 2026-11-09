"""
AgentShield Standalone SDK Example — Decorator-Based Tool Protection

Demonstrates how to protect Python functions using the `@shield.protect_tool`
decorator. The decorator ensures deterministic policy evaluation, argument
validation, human review workflows, and immutable audit logging without
modifying your application logic.
"""

from agentshield import (
    Shield,
    PolicyConfiguration,
    ToolBlockedError,
    ToolReviewRequiredError,
)


def main():
    print("=== AgentShield Decorator Protection Example ===\n")

    # 1. Initialize Shield with a declarative policy
    policy = PolicyConfiguration.from_dict({
        "agents": {
            "billing_agent": {
                "name": "billing_agent",
                "allowed_tools": ["calculate_invoice", "issue_refund"],
                "denied_tools": ["delete_account"],
                "allowed_destinations": ["billing.internal.store"],
            }
        },
        "tools": {
            "calculate_invoice": {
                "max_quantity": 500,
                "allowed_destinations": ["billing.internal.store"],
                "argument_schema": {
                    "account_id": "str",
                    "hours": "float",
                    "rate": "float",
                },
            },
            "issue_refund": {
                "max_amount": 5000.0,
                "required_permissions": ["finance:refund"],
                "allowed_destinations": ["billing.internal.store"],
            },
            "delete_account": {
                "max_amount": 0,
            },
        },
    })

    shield = Shield(policy=policy, review_ttl_seconds=300.0)

    # 2. Decorate Python functions with @shield.protect_tool
    @shield.protect_tool(agent="billing_agent")
    def calculate_invoice(account_id: str, hours: float, rate: float) -> dict:
        """Calculates total billing amount for hours worked."""
        total = hours * rate
        return {"account_id": account_id, "total": total, "status": "calculated"}

    @shield.protect_tool(agent="billing_agent", permissions=["finance:refund"])
    def issue_refund(account_id: str, amount: float, reason: str = "customer request") -> dict:
        """Issues a refund to the customer's account."""
        return {"account_id": account_id, "refunded_amount": amount, "status": "refunded"}

    @shield.protect_tool(agent="billing_agent")
    def delete_account(account_id: str) -> None:
        """Dangerous tool: explicitly denied for billing_agent."""
        raise RuntimeError("Should never be reached!")

    # --- Scenario 1: Legitimate call executes smoothly ---
    print("--- 1. Legitimate Protected Tool Call ---")
    invoice = calculate_invoice(account_id="acc_9901", hours=40.0, rate=85.0)
    print(f"Result: {invoice}\n")

    # --- Scenario 2: Explicitly denied tool fails closed ---
    print("--- 2. Blocked Call (Explicitly Denied Tool) ---")
    try:
        delete_account(account_id="acc_9901")
    except ToolBlockedError as err:
        print(f"Blocked as expected: {err}")
        print(f"Decision: {err.decision.decision.value}, Reasons: {err.reasons}\n")

    # --- Scenario 3: Argument schema mismatch fails closed ---
    print("--- 3. Blocked Call (Schema Type Mismatch) ---")
    try:
        calculate_invoice(account_id="acc_9901", hours="not-a-number", rate=85.0)  # hours must be float
    except ToolBlockedError as err:
        print(f"Blocked schema violation: {err}")
        print(f"Reasons: {err.reasons}\n")

    # --- Scenario 4: High-value transaction requires Human Review ---
    print("--- 4. Escalation to Human Review Queue ---")
    # A $2,500 refund triggers elevated transaction review
    try:
        issue_refund(account_id="acc_9901", amount=2500.0)
    except ToolReviewRequiredError as err:
        print(f"Review required: {err}")
        print(f"Pending Review ID: {err.review_id}")
        print(f"Risk Score: {err.risk_score}\n")

        # Later, an authorized reviewer can review and approve it:
        print("--- 5. Reviewer Approves Enqueued Action ---")
        approval_res = shield.approve_review(err.review_id, approver="carol_supervisor")
        print(f"Approval status: {approval_res.execution_status.value}")
        print(f"Tool executed result: {approval_res.tool_result}\n")

    print("=== Decorator example completed successfully ===")


if __name__ == "__main__":
    main()
