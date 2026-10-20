from dataclasses import dataclass, field
from typing import Any

@dataclass
class Action:
    agent: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not isinstance(self.agent, str) or not self.agent:
            raise ValueError("agent must be a non-empty string")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError("tool must be a non-empty string")
        if not isinstance(self.arguments, dict):
            raise TypeError("arguments must be a dictionary")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dictionary")
