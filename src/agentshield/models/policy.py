from dataclasses import dataclass

@dataclass
class PolicyResult:
    passed: bool
    rule: str
    reason: str
    
    def __post_init__(self):
        if not isinstance(self.passed, bool):
            raise TypeError("passed must be a boolean")
        if not isinstance(self.rule, str) or not self.rule:
            raise ValueError("rule must be a non-empty string")
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")
