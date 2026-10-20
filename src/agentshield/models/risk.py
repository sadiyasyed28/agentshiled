from enum import Enum
from dataclasses import dataclass, field

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class RiskResult:
    score: float
    severity: RiskLevel
    factors: list[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not isinstance(self.score, (int, float)):
            raise TypeError("score must be a numeric value")
        if self.score < 0.0 or self.score > 100.0:
            raise ValueError("score must be between 0.0 and 100.0")
        if not isinstance(self.severity, RiskLevel):
            raise TypeError("severity must be a RiskLevel instance")
        if not isinstance(self.factors, list):
            raise TypeError("factors must be a list")
