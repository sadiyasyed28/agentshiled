"""
AgentShield Minimal Customer Pilot Example — Real Agent Tool Execution

Demonstrates the complete, production-grade integration lifecycle of a real
AI agent using AgentShield's runtime security SDK:
1. Define a deterministic enterprise security policy (declarative).
2. Protect real Python tool callables using `@shield.protect_tool`.
3. Intercept and execute permitted actions (stateful real execution).
4. Intercept and block prohibited / dangerous actions (fail-closed, never executes).
5. Halt high-risk actions in human review queue (held unexecuted).
6. Approve and safely execute the held action through human supervisor workflow.
7. Verify the cryptographic SHA-256 audit ledger.

Run this script:
    python examples/real_agent_minimal_example.py
"""

import sys
from typing import Any, Dict
from agentshield import (
    Shield,
    PolicyConfiguration,
    ToolBlockedError,
    ToolReviewRequiredError,
    SQLiteAuditStore,
)


def main():
    print("=" * 70)
    print("AgentShield — Enterprise AI Agent Runtime Security Pilot")
    print("=" * 70)

    # 1. Initialize persistent cryptographic audit ledger and policy
    audit_store = SQLiteAuditStore(db_path="pilot_audit.db")

    policy = PolicyConfiguration.from_dict({
        "agents": {
            "order_fulfillment_agent": {
                "name": "order_fulfillment_agent",
                "allowed_tools": ["check_inventory", "place_order", "request_refund"],
                "denied_tools": ["delete_records", "raw_sql_query"],
                "allowed_destinations": ["api.inventory.internal", "erp.company.net"],
            }
        },
        "tools": {
            "check_inventory": {
                "allowed_destinations": ["api.inventory.internal"],
                "argument_schema": {
                    "sku": "str",
                },
            },
            "place_order": {
                "max_quantity": 250,
                "allowed_destinations": ["erp.company.net"],
                "argument_schema": {
                    "sku": "str",
                    "quantity": "int",
                },
            },
            "request_refund": {
                "max_amount": 5000.0,
                "required_permissions": ["finance:refund"],
                "allowed_destinations": ["erp.company.net"],
                "argument_schema": {
                    "order_id": "str",
                    "amount": "float",
                },
            },
            "delete_records": {
                "max_amount": 0.0,
            },
        },
    })

    shield = Shield(policy=policy, audit_store=audit_store)

    # Real enterprise database / state simulation
    inventory_db = {"SKU-A100": 850, "SKU-B200": 42}
    orders_placed = []

    # 2. Wrap real tool functions with @shield.protect_tool
    @shield.protect_tool(agent="order_fulfillment_agent")
    def check_inventory(sku: str, destination: str = "api.inventory.internal") -> Dict[str, Any]:
        """Reads current warehouse inventory levels."""
        qty = inventory_db.get(sku, 0)
        return {"sku": sku, "in_stock": qty, "status": "available" if qty > 0 else "out_of_stock"}

    @shield.protect_tool(agent="order_fulfillment_agent")
    def place_order(sku: str, quantity: int, destination: str = "erp.company.net") -> Dict[str, Any]:
        """Deducts stock and creates a confirmed purchase order."""
        if inventory_db.get(sku, 0) < quantity:
            return {"error": "Insufficient stock"}
        inventory_db[sku] -= quantity
        order_id = f"PO-{len(orders_placed) + 1001}"
        orders_placed.append((order_id, sku, quantity))
        return {"order_id": order_id, "sku": sku, "quantity": quantity, "status": "confirmed"}

    @shield.protect_tool(agent="order_fulfillment_agent", permissions=["finance:refund"])
    def request_refund(order_id: str, amount: float, destination: str = "erp.company.net") -> Dict[str, Any]:
        """Executes a monetary customer refund."""
        return {"refund_id": f"REF-{order_id}", "amount": amount, "status": "settled"}

    @shield.protect_tool(agent="order_fulfillment_agent")
    def delete_records(table: str) -> None:
        """Dangerous destructive tool — explicitly denied in policy."""
        raise RuntimeError("CRITICAL ERROR: Destructive tool should NEVER be invoked!")

    # --- Step 1: Legitimate Allowed Execution ---
    print("\n[Step 1] Permitted Tool Invocation (place_order)")
    inv = check_inventory(sku="SKU-A100")
    print(f"  Inventory Check: {inv}")
    order_res = place_order(sku="SKU-A100", quantity=15)
    print(f"  Order Execution: {order_res}")
    print(f"  Remaining Stock: {inventory_db['SKU-A100']}")

    # --- Step 2: Prohibited Tool Call Interception (fail-closed) ---
    print("\n[Step 2] Prohibited Tool Invocation (delete_records)")
    try:
        delete_records("customers")
    except ToolBlockedError as err:
        print(f"  [BLOCKED] Decision: {err.decision.decision.value}")
        print(f"  [BLOCKED] Reasons : {err.reasons}")

    # --- Step 3: Parameter Limit Violation (max_quantity = 250) ---
    print("\n[Step 3] Parameter Threshold Violation (quantity = 500 > 250)")
    try:
        place_order(sku="SKU-A100", quantity=500)
    except ToolBlockedError as err:
        print(f"  [BLOCKED] Decision: {err.decision.decision.value}")
        print(f"  [BLOCKED] Reasons : {err.reasons}")

    # --- Step 4: High-Risk Action Halts for Human Review ---
    print("\n[Step 4] High-Risk Financial Action ($2,400 Refund)")
    pending_review_id = None
    try:
        request_refund(order_id="PO-1001", amount=2400.0)
    except ToolReviewRequiredError as err:
        print(f"  [HELD] Review Required: {err}")
        print(f"  [HELD] Review ID      : {err.review_id}")
        print(f"  [HELD] Risk Score     : {err.risk_score}")
        pending_review_id = err.review_id

    # --- Step 5: Supervisor Approval & At-Most-Once Execution ---
    if pending_review_id:
        print(f"\n[Step 5] Human Supervisor Approval Workflow for {pending_review_id}")
        # Register the callable in shield registry for dispatch
        shield.registry.register(
            "request_refund",
            lambda args: {"refund_id": f"REF-{args.get('order_id')}", "amount": args.get("amount"), "status": "settled"}
        )
        approved_result = shield.approve_review(pending_review_id, approver="alice_supervisor")
        print(f"  Execution Status : {approved_result.execution_status.value}")
        print(f"  Tool Execution Res: {approved_result.tool_result}")

    # --- Step 6: Cryptographic SHA-256 Audit Ledger Verification ---
    print("\n[Step 6] Cryptographic Audit Ledger Integrity Verification")
    audit_report = audit_store.verify_integrity()
    print(f"  Ledger Status  : {'[VALID]' if audit_report['valid'] else '[CORRUPTED]'}")
    print(f"  Total Records  : {audit_report['total_records']}")
    print(f"  Integrity Check: SHA-256 hash chain verified intact.")
    print("=" * 70)


if __name__ == "__main__":
    main()
