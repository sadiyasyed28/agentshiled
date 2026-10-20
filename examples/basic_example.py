from agentshield import Shield

def print_decision(title, agent, tool, arguments, decision):
    print(f"--- {title} ---")
    print(f"ACTION: agent='{agent}', tool='{tool}', arguments={arguments}")
    print(f"DECISION: {decision.decision.value}")
    print(f"ALLOWED: {decision.allowed}")
    print(f"REASONS: {decision.reasons}")
    print()

def main():
    shield = Shield()
    print("Initializing AgentShield Basic Example...\n")

    # 1. Legitimate action
    agent1 = "shopping_agent"
    tool1 = "create_order"
    args1 = {"product": "shoes", "quantity": 2}
    decision1 = shield.authorize(agent=agent1, tool=tool1, arguments=args1)
    print_decision("1. Legitimate Action", agent1, tool1, args1, decision1)

    # 2. Invalid action
    agent2 = ""
    tool2 = "create_order"
    args2 = {"product": "shoes"}
    decision2 = shield.authorize(agent=agent2, tool=tool2, arguments=args2)
    print_decision("2. Invalid Action (Missing Agent Name)", agent2, tool2, args2, decision2)

    # 3. Unknown tool
    agent3 = "shopping_agent"
    tool3 = "delete_database"
    args3 = {}
    decision3 = shield.authorize(agent=agent3, tool=tool3, arguments=args3)
    print_decision("3. Unknown Tool", agent3, tool3, args3, decision3)

if __name__ == "__main__":
    main()
