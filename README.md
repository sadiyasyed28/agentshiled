# AgentShield

AgentShield is an open-source runtime security and control layer for AI agents.

## Core Architecture
An AI agent can propose an action (e.g., calling a tool or API). AgentShield sits strictly between the AI agent and the real tool. It intercepts the proposed action, runs deterministic policies, and evaluates risk before allowing, reviewing, or blocking the execution. Crucially, the LLM is NOT the final security authority.

## Current Project Status
The project is currently in the initial setup phase (Phase 0).

## Development
This project is being developed incrementally. Future phases will introduce the core shield engine, policy evaluations, and risk analyzers.

## Examples

To run the basic demonstration, use the following command:

```bash
python examples/basic_example.py
```
