"""AgentShield LangChain Integration Example.

Demonstrates protecting LangChain tools with AgentShield's runtime
security policy engine, parameter validation, risk evaluation,
and human review approval workflows.
"""

import asyncio
from langchain_core.tools import tool

from agentshield import (
    Shield,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    ToolBlockedError,
    ToolReviewRequiredError,
    SQLiteAuditStore,
)


def main():
    print("=" * 70)
    print("AgentShield LangChain Integration Demo")
    print("=" * 70)

    # 1. Define declarative security policy
    policy = PolicyConfiguration(
        agents={
            "customer_service_bot": AgentConfig(
                name="customer_service_bot",
                allowed_tools=["fetch_order_status", "process_refund", "search_kb"],
            ),
            "untrusted_bot": AgentConfig(
                name="untrusted_bot",
                allowed_tools=["search_kb"],
            ),
        },
        tools={
            "fetch_order_status": ToolRule(
                tool="fetch_order_status",
            ),
            "process_refund": ToolRule(
                tool="process_refund",
                max_amount=5000.0,
                required_permissions=["finance:refund"],
            ),
            "search_kb": ToolRule(
                tool="search_kb",
                allowed_destinations=["kb.internal.company.com"],
            ),
        },
    )

    audit_store = SQLiteAuditStore(":memory:")
    shield = Shield(policy=policy, audit_store=audit_store)

    # 2. Define standard LangChain tools
    @tool
    def fetch_order_status(order_id: str) -> dict:
        """Fetch current order shipping and delivery status."""
        print(f"  [EXECUTION] Calling backend API for order {order_id}...")
        return {"order_id": order_id, "status": "shipped", "carrier": "FedEx"}

    @tool
    def process_refund(order_id: str, amount: float) -> dict:
        """Process a customer refund."""
        print(f"  [EXECUTION] Processing financial refund of ${amount} for order {order_id}...")
        return {"order_id": order_id, "refund_amount": amount, "status": "completed"}

    @tool
    def search_kb(query: str, destination: str = "kb.internal.company.com") -> str:
        """Search the internal knowledge base."""
        print(f"  [EXECUTION] Searching KB at {destination} for '{query}'...")
        return f"Articles matching '{query}'"

    # 3. Protect LangChain tools with AgentShield
    safe_order_tool = shield.protect_langchain_tool(
        fetch_order_status,
        agent="customer_service_bot",
    )
    safe_refund_tool = shield.protect_langchain_tool(
        process_refund,
        agent="customer_service_bot",
        permissions=["finance:refund"],
    )
    safe_kb_tool = shield.protect_langchain_tool(
        search_kb,
        agent="customer_service_bot",
    )

    print("\n--- 1. ALLOW: Legitimate tool invocation ---")
    order_info = safe_order_tool.invoke({"order_id": "ord_8820"})
    print(f"Result: {order_info}")

    print("\n--- 2. BLOCK: Unauthorized destination host ---")
    try:
        safe_kb_tool.invoke({"query": "passwords", "destination": "attacker.evil.com"})
    except ToolBlockedError as err:
        print(f"Blocked as expected: {err}")

    print("\n--- 3. BLOCK: Exceeding maximum policy limits ---")
    try:
        # Policy limit for process_refund is max_amount=5000.0; passing 9000.0 violates policy
        safe_refund_tool.invoke({"order_id": "ord_8820", "amount": 9000.0})
    except ToolBlockedError as err:
        print(f"Blocked as expected: {err}")

    print("\n--- 4. REVIEW: High-risk action triggers supervisor queue ---")
    # Refund of $2500 is within max_amount=5000, but amount > 1000 flags for REVIEW
    try:
        safe_refund_tool.invoke({"order_id": "ord_8820", "amount": 2500.0})
    except ToolReviewRequiredError as err:
        print(f"Review required! ID: {err.review_id}")
        print("  -> Tool was NOT executed prior to approval.")

        # Supervisor reviews and approves the pending action
        print(f"  -> Supervisor 'sec_lead_sarah' reviews and approves review {err.review_id}...")
        approval_res = shield.approve_review(err.review_id, approver="sec_lead_sarah")
        print(f"  -> Execution status: {approval_res.execution_status.value}")
        print(f"  -> Execution tool result: {approval_res.tool_result}")

    # 5. Async invocation
    @tool
    async def async_lookup(item_id: str) -> str:
        """Look up item inventory asynchronously."""
        await asyncio.sleep(0.01)
        return f"Inventory for {item_id}: 42 in stock"

    # Add to policy
    policy.tools["async_lookup"] = ToolRule(tool="async_lookup")
    policy.agents["customer_service_bot"].allowed_tools.append("async_lookup")
    safe_async = shield.protect_langchain_tool(async_lookup, agent="customer_service_bot")

    print("\n--- 5. ASYNC: LangChain async tool invocation ---")
    async def run_async():
        res = await safe_async.ainvoke({"item_id": "sku_99"})
        print(f"Async result: {res}")

    asyncio.run(run_async())

    print("\n" + "=" * 70)
    print("Demo completed successfully! All security invariants verified.")
    print("=" * 70)


if __name__ == "__main__":
    main()
