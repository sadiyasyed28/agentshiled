from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from agentshield.models import Action, RiskLevel, RiskResult

# Centralized severity thresholds in one place
# LOW: 0 - 29, MEDIUM: 30 - 59, HIGH: 60 - 84, CRITICAL: 85 - 100
LOW_MAX = 29.0
MEDIUM_MAX = 59.0
HIGH_MAX = 84.0

DANGEROUS_ACTIONS = {
    "delete_database",
    "drop_table",
    "format_disk",
    "shutdown",
    "execute_script",
    "run_command",
    "bash",
    "shell",
    "eval",
}

FINANCIAL_TOOLS = {
    "refund_order",
    "transfer_funds",
    "withdraw",
    "send_payment",
}

PRIVILEGED_ROLES = {
    "admin",
    "root",
    "superuser",
    "system",
}

from agentshield.detector.prompt_injection import PromptInjectionDetector

@dataclass(frozen=True)
class FactorDefinition:
    name: str
    weight: float
    explanation: str

class RiskEngine:
    """
    Deterministic risk scoring engine for AgentShield.
    Computes score between 0 and 100 and maps to centralized RiskLevel.
    Deduplicates risk factors with short explanations.
    """

    def __init__(self, detector: Optional[PromptInjectionDetector] = None):
        self.detector = detector or PromptInjectionDetector()

    @staticmethod
    def calculate_severity(score: float) -> RiskLevel:
        if score <= LOW_MAX:
            return RiskLevel.LOW
        elif score <= MEDIUM_MAX:
            return RiskLevel.MEDIUM
        elif score <= HIGH_MAX:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def evaluate(
        self,
        action: Optional[Action] = None,
        user_input: Optional[str] = None,
        permissions: Optional[List[str]] = None,
    ) -> RiskResult:
        factors_dict: Dict[str, str] = {}
        score = 0.0

        def add_factor(def_factor: FactorDefinition):
            nonlocal score
            if def_factor.name not in factors_dict:
                factors_dict[def_factor.name] = f"{def_factor.name}: {def_factor.explanation}"
                score += def_factor.weight

        # 1. Action evaluation
        if action:
            tool_lower = action.tool.lower().strip()
            agent_lower = action.agent.lower().strip()

            # Destructive/dangerous tools
            if tool_lower in DANGEROUS_ACTIONS or any(d in tool_lower for d in ("delete", "drop", "destroy", "format")):
                add_factor(FactorDefinition(
                    name="destructive_tool",
                    weight=85.0,
                    explanation="Action targets potentially destructive tool or database operation"
                ))

            # Financial tools
            if tool_lower in FINANCIAL_TOOLS or any(f in tool_lower for f in ("refund", "transfer", "payout", "payment")):
                add_factor(FactorDefinition(
                    name="financial_impact",
                    weight=40.0,
                    explanation="Action performs financial or monetary transaction"
                ))

            # Argument size / quantity risks
            args = action.arguments or {}
            qty = args.get("quantity")
            if isinstance(qty, (int, float)):
                if qty > 50:
                    add_factor(FactorDefinition(
                        name="high_quantity_bulk",
                        weight=50.0,
                        explanation="Operation quantity exceeds high bulk threshold"
                    ))
                elif qty > 10:
                    add_factor(FactorDefinition(
                        name="elevated_quantity",
                        weight=35.0,
                        explanation="Operation quantity exceeds standard threshold"
                    ))

            amount = args.get("amount")
            if isinstance(amount, (int, float)):
                if amount > 5000:
                    add_factor(FactorDefinition(
                        name="high_transaction_amount",
                        weight=50.0,
                        explanation="Transaction amount is exceptionally high"
                    ))
                elif amount > 1000:
                    add_factor(FactorDefinition(
                        name="elevated_transaction_amount",
                        weight=30.0,
                        explanation="Transaction amount is elevated"
                    ))

            # Scan arguments with prompt injection detector
            injection_findings = self.detector.scan_arguments(action.arguments)
            for finding in injection_findings:
                weight = 85.0 if finding.severity == RiskLevel.CRITICAL else (60.0 if finding.severity == RiskLevel.HIGH else 30.0)
                add_factor(FactorDefinition(
                    name=f"injection_{finding.pattern_id}",
                    weight=weight,
                    explanation=f"[{finding.matched_field}] {finding.explanation}"
                ))

            # Privileged agent role
            if agent_lower in PRIVILEGED_ROLES or "admin" in agent_lower:
                add_factor(FactorDefinition(
                    name="privileged_agent",
                    weight=20.0,
                    explanation="Action executed by high-privilege administrative agent"
                ))

        # 2. User input inspection (if provided)
        if user_input:
            input_lower = user_input.lower()
            if any(cmd in input_lower for cmd in ("rm -rf", "drop table", "shutdown", "format ")):
                add_factor(FactorDefinition(
                    name="destructive_command_pattern",
                    weight=90.0,
                    explanation="User input contains explicit destructive command syntax"
                ))
            
            # Scan user input with detector
            input_findings = self.detector.scan_text(user_input, field_name="user_input")
            for finding in input_findings:
                weight = 85.0 if finding.severity == RiskLevel.CRITICAL else (60.0 if finding.severity == RiskLevel.HIGH else 30.0)
                add_factor(FactorDefinition(
                    name=f"injection_{finding.pattern_id}",
                    weight=weight,
                    explanation=f"[{finding.matched_field}] {finding.explanation}"
                ))

        # Clamp score between 0.0 and 100.0
        final_score = min(max(float(score), 0.0), 100.0)
        severity = self.calculate_severity(final_score)
        unique_factors = sorted(list(factors_dict.values()))

        return RiskResult(
            score=final_score,
            severity=severity,
            factors=unique_factors
        )
