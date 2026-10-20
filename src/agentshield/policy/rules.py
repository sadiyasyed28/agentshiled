from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class AgentConfig:
    name: str
    allowed_tools: List[str] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)

@dataclass
class ToolRule:
    tool: str
    max_quantity: float = float('inf')
    max_amount: float = float('inf')
    required_permissions: List[str] = field(default_factory=list)

@dataclass
class PolicyConfiguration:
    agents: Dict[str, AgentConfig] = field(default_factory=dict)
    tools: Dict[str, ToolRule] = field(default_factory=dict)
