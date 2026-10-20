from agentshield import Shield

def main():
    shield = Shield()
    
    # 1. Register a fake tool
    def fake_create_order(arguments):
        print(f"   [TOOL EXECUTING] Creating order with: {arguments}")
        return {"order_id": "12345", "status": "success"}

    shield.registry.register("create_order", fake_create_order)
    
    print("--- 1. Legitimate Request ---")
    res = shield.execute(agent="shopping_agent", tool="create_order", arguments={"product": "shoes", "quantity": 2})
    print("SECURITY DECISION:", res.decision.decision.value)
    print("TOOL EXECUTION:", res.tool_result)
    print()
    
    print("--- 2. Blocked Request (Unknown Tool) ---")
    res2 = shield.execute(agent="shopping_agent", tool="delete_database", arguments={})
    print("SECURITY DECISION:", res2.decision.decision.value)
    print("TOOL EXECUTION:", res2.tool_result)
    print()

    print("--- 3. Blocked Request (Unauthorized Agent) ---")
    res3 = shield.execute(agent="evil_agent", tool="create_order", arguments={"product": "poison"})
    print("SECURITY DECISION:", res3.decision.decision.value)
    print("TOOL EXECUTION:", res3.tool_result)
    print()

if __name__ == "__main__":
    main()
