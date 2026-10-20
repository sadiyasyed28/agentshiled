from dataclasses import dataclass, field
from typing import Callable, Any, Dict, Optional

@dataclass
class RegisteredTool:
    name: str
    callable_func: Callable[[Dict[str, Any]], Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, RegisteredTool] = {}

    def register(self, name: str, callable_func: Callable[[Dict[str, Any]], Any], 
                 metadata: Optional[Dict[str, Any]] = None, 
                 required_permissions: Optional[list[str]] = None):
        self._tools[name] = RegisteredTool(
            name=name,
            callable_func=callable_func,
            metadata=metadata or {},
            required_permissions=required_permissions or []
        )

    def get_tool(self, name: str) -> Optional[RegisteredTool]:
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        return name in self._tools
