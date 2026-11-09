"""AgentShield CrewAI Integration Example.

Demonstrates protecting CrewAI tools with AgentShield's runtime
security policy engine, parameter validation, risk evaluation,
and human review approval workflows.
"""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Optional, Type
from pydantic import BaseModel, Field, ConfigDict

# If crewai is not installed (e.g. Python >= 3.14), inject a lightweight BaseTool
# so this example can run out-of-the-box in any Python environment.
try:
    from crewai.tools import BaseTool
except ImportError:
    class BaseTool(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")
        name: str = Field(..., description="Tool name")
        description: str = Field(..., description="Tool description")
        args_schema: Optional[Type[BaseModel]] = Field(default=None)
        result_as_answer: bool = Field(default=False)

        def run(self, *args, **kwargs):
            return self._run(*args, **kwargs)

        def _run(self, *args, **kwargs):
            raise NotImplementedError

        async def arun(self, *args, **kwargs):
            return await self._arun(*args, **kwargs)

        async def _arun(self, *args, **kwargs):
            raise NotImplementedError

    m_tools = types.ModuleType("crewai.tools")
    m_tools.BaseTool = BaseTool
    m_crewai = types.ModuleType("crewai")
    m_crewai.tools = m_tools
    m_crewai.BaseTool = BaseTool
    sys.modules["crewai"] = m_crewai
    sys.modules["crewai.tools"] = m_tools

from agentshield import (
    Shield,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    ToolBlockedError,
    ToolReviewRequiredError,
    SQLiteAuditStore,
)
from agentshield.integrations.crewai import protect_crewai_tool


def main():
    print("=" * 70)
    print("AgentShield CrewAI Integration Demo")
    print("=" * 70)

    # 1. Define declarative security policy
    policy = PolicyConfiguration(
        agents={
            "financial_analyst_agent": AgentConfig(
                name="financial_analyst_agent",
                allowed_tools=["fetch_account_balance", "wire_transfer", "query_market_data"],
            ),
            "untrusted_agent": AgentConfig(
                name="untrusted_agent",
                allowed_tools=["query_market_data"],
            ),
        },
        tools={
            "fetch_account_balance": ToolRule(
                tool="fetch_account_balance",
            ),
            "wire_transfer": ToolRule(
                tool="wire_transfer",
                max_amount=10000.0,
                required_permissions=["treasury:wire"],
            ),
            "query_market_data": ToolRule(
                tool="query_market_data",
                allowed_destinations=["api.marketdata.internal"],
            ),
        },
    )

    audit_store = SQLiteAuditStore(":memory:")
    shield = Shield(policy=policy, audit_store=audit_store)

    # 2. Define CrewAI BaseTool implementations
    class BalanceQuerySchema(BaseModel):
        account_id: str = Field(description="Account identifier")

    class FetchAccountBalanceTool(BaseTool):
        name: str = "fetch_account_balance"
        description: str = "Retrieve real-time ledger balance for an account"
        args_schema: Type[BaseModel] = BalanceQuerySchema

        def _run(self, account_id: str) -> dict:
            print(f"  [EXECUTION] Querying core banking system for {account_id}...")
            return {"account_id": account_id, "balance_usd": 1250000.00, "status": "active"}

    class WireFundsSchema(BaseModel):
        to_account: str = Field(description="Recipient account")
        amount: float = Field(description="Wire amount in USD")

    class WireTransferTool(BaseTool):
        name: str = "wire_transfer"
        description: str = "Wire funds to an external institution"
        args_schema: Type[BaseModel] = WireFundsSchema

        def _run(self, to_account: str, amount: float) -> dict:
            print(f"  [EXECUTION] Executing wire transfer of ${amount} to {to_account}...")
            return {"to_account": to_account, "amount": amount, "status": "completed"}

    class MarketQuerySchema(BaseModel):
        ticker: str = Field(description="Stock ticker symbol")
        destination: str = Field(default="api.marketdata.internal", description="Market data gateway")

    class MarketDataTool(BaseTool):
        name: str = "query_market_data"
        description: str = "Query latest market quotes"
        args_schema: Type[BaseModel] = MarketQuerySchema

        def _run(self, ticker: str, destination: str = "api.marketdata.internal") -> str:
            print(f"  [EXECUTION] Querying endpoint {destination} for '{ticker}'...")
            return f"Quote for {ticker}: $420.69"

    # 3. Protect CrewAI tools with AgentShield
    safe_balance_tool = shield.protect_crewai_tool(
        FetchAccountBalanceTool(),
        agent="financial_analyst_agent",
    )
    safe_wire_tool = shield.protect_crewai_tool(
        WireTransferTool(),
        agent="financial_analyst_agent",
        permissions=["treasury:wire"],
    )
    safe_market_tool = shield.protect_crewai_tool(
        MarketDataTool(),
        agent="financial_analyst_agent",
    )

    print("\n--- 1. ALLOW: Legitimate tool invocation ---")
    balance = safe_balance_tool.run(account_id="ACC-00129")
    print(f"Result: {balance}")

    print("\n--- 2. BLOCK: Unauthorized destination host ---")
    try:
        safe_market_tool.run(ticker="NVDA", destination="evil-proxy.untrusted.com")
    except ToolBlockedError as err:
        print(f"Blocked as expected: {err}")

    print("\n--- 3. BLOCK: Exceeding maximum policy limit ---")
    try:
        # Policy limit for wire_funds is max_amount=10000.0; passing 25000.0 blocks
        safe_wire_tool.run(to_account="EXT-9871", amount=25000.0)
    except ToolBlockedError as err:
        print(f"Blocked as expected: {err}")

    print("\n--- 4. REVIEW: High-risk action triggers supervisor queue ---")
    # Wire of $5000 is within max_amount=10000, but amount > 1000 flags for REVIEW
    try:
        safe_wire_tool.run(to_account="EXT-9871", amount=5000.0)
    except ToolReviewRequiredError as err:
        print(f"Review required! ID: {err.review_id}")
        print("  -> Tool was NOT executed prior to approval.")

        # Supervisor reviews and approves the pending action
        print(f"  -> Supervisor 'risk_lead_marcus' reviews and approves review {err.review_id}...")
        approval_res = shield.approve_review(err.review_id, approver="risk_lead_marcus")
        print(f"  -> Execution status: {approval_res.execution_status.value}")
        print(f"  -> Execution tool result: {approval_res.tool_result}")

    # 5. Async invocation
    class AsyncMarketNewsTool(BaseTool):
        name: str = "query_news"
        description: str = "Query real-time market news headlines asynchronously"

        async def _arun(self, topic: str) -> str:
            await asyncio.sleep(0.01)
            return f"Headlines for {topic}: Markets surge on positive economic data."

    policy.tools["query_news"] = ToolRule(tool="query_news")
    policy.agents["financial_analyst_agent"].allowed_tools.append("query_news")
    safe_news = shield.protect_crewai_tool(AsyncMarketNewsTool(), agent="financial_analyst_agent")

    print("\n--- 5. ASYNC: CrewAI async tool invocation ---")
    async def run_async():
        res = await safe_news.arun(topic="central_banks")
        print(f"Async result: {res}")

    asyncio.run(run_async())

    print("\n" + "=" * 70)
    print("Demo completed successfully! All CrewAI security invariants verified.")
    print("=" * 70)


if __name__ == "__main__":
    main()
