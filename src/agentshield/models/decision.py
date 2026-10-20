from enum import Enum
from dataclasses import dataclass
from .risk import RiskLevel

class DecisionValue(Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"

@dataclass
class Decision:
    allowed: bool
    decision: DecisionValue
    reasons: list[str]
    risk_score: float
    severity: RiskLevel
    agent: str
    tool: str
    
    def __post_init__(self):
        if not isinstance(self.allowed, bool):
            raise TypeError("allowed must be a boolean")
        if not isinstance(self.decision, DecisionValue):
            raise TypeError("decision must be a DecisionValue instance")
        if not isinstance(self.reasons, list):
            raise TypeError("reasons must be a list")
        if not isinstance(self.risk_score, (int, float)):
            raise TypeError("risk_score must be a numeric value")
        if not isinstance(self.severity, RiskLevel):
            raise TypeError("severity must be a RiskLevel instance")
        if not isinstance(self.agent, str) or not self.agent:
            raise ValueError("agent must be a non-empty string")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError("tool must be a non-empty string")
