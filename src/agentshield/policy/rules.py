from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, TextIO
import hashlib
import json


class PolicyValidationError(ValueError):
    """Raised when a declarative policy configuration is malformed, invalid, or inconsistent."""
    pass


SUPPORTED_SCHEMA_TYPES: Dict[str, type] = {
    "str": str,
    "string": str,
    "int": int,
    "integer": int,
    "float": float,
    "number": float,
    "bool": bool,
    "boolean": bool,
    "dict": dict,
    "object": dict,
    "list": list,
    "array": list,
}


@dataclass
class AgentConfig:
    name: str
    allowed_tools: List[str] = field(default_factory=list)
    denied_tools: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)


@dataclass
class ToolRule:
    tool: str
    max_quantity: float = float('inf')
    max_amount: float = float('inf')
    required_permissions: List[str] = field(default_factory=list)
    allowed_destinations: List[str] = field(default_factory=list)
    argument_schema: Optional[Dict[str, type]] = None


@dataclass
class PolicyConfiguration:
    agents: Dict[str, AgentConfig] = field(default_factory=dict)
    tools: Dict[str, ToolRule] = field(default_factory=dict)

    def compute_version_hash(self) -> str:
        """Deterministically computes a sha256 version hash of the policy configuration."""
        data = {
            "agents": {
                k: {
                    "name": v.name,
                    "allowed_tools": sorted(v.allowed_tools),
                    "denied_tools": sorted(v.denied_tools),
                    "allowed_destinations": sorted(v.allowed_destinations),
                }
                for k, v in sorted(self.agents.items())
            },
            "tools": {
                k: {
                    "tool": v.tool,
                    "max_quantity": v.max_quantity if v.max_quantity != float('inf') else "inf",
                    "max_amount": v.max_amount if v.max_amount != float('inf') else "inf",
                    "required_permissions": sorted(v.required_permissions),
                    "allowed_destinations": sorted(v.allowed_destinations),
                }
                for k, v in sorted(self.tools.items())
            }
        }
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Converts the policy configuration into a serializable dictionary."""
        return {
            "agents": {
                name: {
                    "name": agent.name,
                    "allowed_tools": list(agent.allowed_tools),
                    "denied_tools": list(agent.denied_tools),
                    "allowed_destinations": list(agent.allowed_destinations),
                }
                for name, agent in self.agents.items()
            },
            "tools": {
                name: {
                    "tool": tool.tool,
                    "max_quantity": tool.max_quantity if tool.max_quantity != float("inf") else "inf",
                    "max_amount": tool.max_amount if tool.max_amount != float("inf") else "inf",
                    "required_permissions": list(tool.required_permissions),
                    "allowed_destinations": list(tool.allowed_destinations),
                    "argument_schema": {
                        p: t.__name__ for p, t in tool.argument_schema.items()
                    } if tool.argument_schema else None,
                }
                for name, tool in self.tools.items()
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConfiguration":
        """Constructs and validates a PolicyConfiguration from a dictionary.

        Args:
            data: Dictionary containing declarative 'agents' and/or 'tools' definitions.

        Raises:
            PolicyValidationError: If the structure is malformed, missing required fields,
                                   contains unknown keys, or specifies contradictory rules.
        """
        if not isinstance(data, dict):
            raise PolicyValidationError(
                f"Policy configuration must be a dictionary, got {type(data).__name__}"
            )

        allowed_root_keys = {"agents", "tools", "version", "metadata"}
        unknown_root_keys = set(data.keys()) - allowed_root_keys
        if unknown_root_keys:
            sorted_keys = ", ".join(f"'{k}'" for k in sorted(unknown_root_keys))
            raise PolicyValidationError(f"Unknown root field(s) in policy configuration: {sorted_keys}")

        # 1. Parse and validate agents
        agents_data = data.get("agents")
        agents_dict: Dict[str, AgentConfig] = {}

        if agents_data is not None:
            if isinstance(agents_data, dict):
                for agent_key, agent_val in agents_data.items():
                    if not isinstance(agent_key, str) or not agent_key.strip():
                        raise PolicyValidationError(
                            f"Agent key must be a non-empty string, got {agent_key!r}"
                        )
                    if not isinstance(agent_val, dict):
                        raise PolicyValidationError(
                            f"Agent '{agent_key}' configuration must be a dictionary, got {type(agent_val).__name__}"
                        )

                    allowed_agent_keys = {"name", "allowed_tools", "denied_tools", "allowed_destinations"}
                    unknown_agent_keys = set(agent_val.keys()) - allowed_agent_keys
                    if unknown_agent_keys:
                        sorted_keys = ", ".join(f"'{k}'" for k in sorted(unknown_agent_keys))
                        raise PolicyValidationError(
                            f"Agent '{agent_key}' contains unknown field(s): {sorted_keys}"
                        )

                    agent_name = agent_val.get("name", agent_key)
                    if not isinstance(agent_name, str) or not agent_name.strip():
                        raise PolicyValidationError(
                            f"Agent '{agent_key}': 'name' must be a non-empty string"
                        )

                    allowed_tools = _validate_string_list(
                        agent_val.get("allowed_tools", []),
                        context=f"Agent '{agent_name}': 'allowed_tools'"
                    )
                    denied_tools = _validate_string_list(
                        agent_val.get("denied_tools", []),
                        context=f"Agent '{agent_name}': 'denied_tools'"
                    )
                    allowed_destinations = _validate_string_list(
                        agent_val.get("allowed_destinations", []),
                        context=f"Agent '{agent_name}': 'allowed_destinations'"
                    )

                    contradictions = set(allowed_tools).intersection(set(denied_tools))
                    if contradictions:
                        raise PolicyValidationError(
                            f"Agent '{agent_name}' has contradictory tools configured in both "
                            f"allowed_tools and denied_tools: {sorted(contradictions)}"
                        )

                    agents_dict[agent_name] = AgentConfig(
                        name=agent_name,
                        allowed_tools=allowed_tools,
                        denied_tools=denied_tools,
                        allowed_destinations=allowed_destinations,
                    )

            elif isinstance(agents_data, list):
                for idx, agent_item in enumerate(agents_data):
                    if not isinstance(agent_item, dict):
                        raise PolicyValidationError(
                            f"Agent at index {idx} must be a dictionary, got {type(agent_item).__name__}"
                        )

                    allowed_agent_keys = {"name", "allowed_tools", "denied_tools", "allowed_destinations"}
                    unknown_agent_keys = set(agent_item.keys()) - allowed_agent_keys
                    if unknown_agent_keys:
                        sorted_keys = ", ".join(f"'{k}'" for k in sorted(unknown_agent_keys))
                        raise PolicyValidationError(
                            f"Agent at index {idx} contains unknown field(s): {sorted_keys}"
                        )

                    agent_name = agent_item.get("name")
                    if not isinstance(agent_name, str) or not agent_name.strip():
                        raise PolicyValidationError(
                            f"Agent at index {idx} must specify a non-empty 'name' string"
                        )
                    if agent_name in agents_dict:
                        raise PolicyValidationError(
                            f"Duplicate agent definition for '{agent_name}'"
                        )

                    allowed_tools = _validate_string_list(
                        agent_item.get("allowed_tools", []),
                        context=f"Agent '{agent_name}': 'allowed_tools'"
                    )
                    denied_tools = _validate_string_list(
                        agent_item.get("denied_tools", []),
                        context=f"Agent '{agent_name}': 'denied_tools'"
                    )
                    allowed_destinations = _validate_string_list(
                        agent_item.get("allowed_destinations", []),
                        context=f"Agent '{agent_name}': 'allowed_destinations'"
                    )

                    contradictions = set(allowed_tools).intersection(set(denied_tools))
                    if contradictions:
                        raise PolicyValidationError(
                            f"Agent '{agent_name}' has contradictory tools configured in both "
                            f"allowed_tools and denied_tools: {sorted(contradictions)}"
                        )

                    agents_dict[agent_name] = AgentConfig(
                        name=agent_name,
                        allowed_tools=allowed_tools,
                        denied_tools=denied_tools,
                        allowed_destinations=allowed_destinations,
                    )
            else:
                raise PolicyValidationError(
                    f"'agents' must be a dictionary or list, got {type(agents_data).__name__}"
                )

        # 2. Parse and validate tools
        tools_data = data.get("tools")
        tools_dict: Dict[str, ToolRule] = {}

        if tools_data is not None:
            if isinstance(tools_data, dict):
                for tool_key, tool_val in tools_data.items():
                    if not isinstance(tool_key, str) or not tool_key.strip():
                        raise PolicyValidationError(
                            f"Tool key must be a non-empty string, got {tool_key!r}"
                        )
                    if not isinstance(tool_val, dict):
                        raise PolicyValidationError(
                            f"Tool '{tool_key}' configuration must be a dictionary, got {type(tool_val).__name__}"
                        )

                    allowed_tool_keys = {
                        "tool",
                        "max_quantity",
                        "max_amount",
                        "required_permissions",
                        "allowed_destinations",
                        "argument_schema",
                    }
                    unknown_tool_keys = set(tool_val.keys()) - allowed_tool_keys
                    if unknown_tool_keys:
                        sorted_keys = ", ".join(f"'{k}'" for k in sorted(unknown_tool_keys))
                        raise PolicyValidationError(
                            f"Tool '{tool_key}' contains unknown field(s): {sorted_keys}"
                        )

                    tool_name = tool_val.get("tool", tool_key)
                    if not isinstance(tool_name, str) or not tool_name.strip():
                        raise PolicyValidationError(
                            f"Tool '{tool_key}': 'tool' name must be a non-empty string"
                        )

                    max_quantity = _validate_limit(tool_val.get("max_quantity"), context=f"Tool '{tool_name}': 'max_quantity'")
                    max_amount = _validate_limit(tool_val.get("max_amount"), context=f"Tool '{tool_name}': 'max_amount'")

                    required_permissions = _validate_string_list(
                        tool_val.get("required_permissions", []),
                        context=f"Tool '{tool_name}': 'required_permissions'"
                    )
                    allowed_destinations = _validate_string_list(
                        tool_val.get("allowed_destinations", []),
                        context=f"Tool '{tool_name}': 'allowed_destinations'"
                    )

                    argument_schema = _validate_argument_schema(
                        tool_val.get("argument_schema"),
                        context=f"Tool '{tool_name}': 'argument_schema'"
                    )

                    tools_dict[tool_name] = ToolRule(
                        tool=tool_name,
                        max_quantity=max_quantity,
                        max_amount=max_amount,
                        required_permissions=required_permissions,
                        allowed_destinations=allowed_destinations,
                        argument_schema=argument_schema,
                    )

            elif isinstance(tools_data, list):
                for idx, tool_item in enumerate(tools_data):
                    if not isinstance(tool_item, dict):
                        raise PolicyValidationError(
                            f"Tool at index {idx} must be a dictionary, got {type(tool_item).__name__}"
                        )

                    allowed_tool_keys = {
                        "tool",
                        "name",
                        "max_quantity",
                        "max_amount",
                        "required_permissions",
                        "allowed_destinations",
                        "argument_schema",
                    }
                    unknown_tool_keys = set(tool_item.keys()) - allowed_tool_keys
                    if unknown_tool_keys:
                        sorted_keys = ", ".join(f"'{k}'" for k in sorted(unknown_tool_keys))
                        raise PolicyValidationError(
                            f"Tool at index {idx} contains unknown field(s): {sorted_keys}"
                        )

                    tool_name = tool_item.get("tool") or tool_item.get("name")
                    if not isinstance(tool_name, str) or not tool_name.strip():
                        raise PolicyValidationError(
                            f"Tool at index {idx} must specify a non-empty 'tool' or 'name' string"
                        )
                    if tool_name in tools_dict:
                        raise PolicyValidationError(
                            f"Duplicate tool definition for '{tool_name}'"
                        )

                    max_quantity = _validate_limit(tool_item.get("max_quantity"), context=f"Tool '{tool_name}': 'max_quantity'")
                    max_amount = _validate_limit(tool_item.get("max_amount"), context=f"Tool '{tool_name}': 'max_amount'")

                    required_permissions = _validate_string_list(
                        tool_item.get("required_permissions", []),
                        context=f"Tool '{tool_name}': 'required_permissions'"
                    )
                    allowed_destinations = _validate_string_list(
                        tool_item.get("allowed_destinations", []),
                        context=f"Tool '{tool_name}': 'allowed_destinations'"
                    )

                    argument_schema = _validate_argument_schema(
                        tool_item.get("argument_schema"),
                        context=f"Tool '{tool_name}': 'argument_schema'"
                    )

                    tools_dict[tool_name] = ToolRule(
                        tool=tool_name,
                        max_quantity=max_quantity,
                        max_amount=max_amount,
                        required_permissions=required_permissions,
                        allowed_destinations=allowed_destinations,
                        argument_schema=argument_schema,
                    )
            else:
                raise PolicyValidationError(
                    f"'tools' must be a dictionary or list, got {type(tools_data).__name__}"
                )

        return cls(agents=agents_dict, tools=tools_dict)

    @classmethod
    def from_yaml(cls, source: Union[str, Path, TextIO]) -> "PolicyConfiguration":
        """Loads and validates a PolicyConfiguration from a YAML string, file path, or stream.

        Requires PyYAML. If PyYAML is not installed, raises ImportError with instructions.

        Args:
            source: A YAML string, file Path, path string, or open text stream.

        Returns:
            Validated PolicyConfiguration instance.
        """
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to parse YAML policies. "
                "Install it with 'pip install agentshield[yaml]' or 'pip install pyyaml'."
            ) from exc

        if hasattr(source, "read"):
            content = source.read()
        elif isinstance(source, Path):
            if not source.exists():
                raise FileNotFoundError(f"Policy file not found: {source}")
            content = source.read_text(encoding="utf-8")
        elif isinstance(source, str):
            try:
                p = Path(source)
                if p.is_file():
                    content = p.read_text(encoding="utf-8")
                else:
                    content = source
            except (OSError, ValueError):
                content = source
        else:
            raise PolicyValidationError(f"Unsupported YAML source type: {type(source).__name__}")

        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise PolicyValidationError(f"Malformed YAML policy: {exc}") from exc

        if parsed is None:
            return cls(agents={}, tools={})
        if not isinstance(parsed, dict):
            raise PolicyValidationError(f"YAML policy root must be a mapping, got {type(parsed).__name__}")

        return cls.from_dict(parsed)

    @classmethod
    def from_yaml_file(cls, path: Union[str, Path]) -> "PolicyConfiguration":
        """Convenience method to load policy configuration directly from a YAML file."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {p}")
        return cls.from_yaml(p)

    def to_yaml(self) -> str:
        """Serializes the policy configuration to a YAML string.

        Requires PyYAML.
        """
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to export YAML policies. "
                "Install it with 'pip install agentshield[yaml]' or 'pip install pyyaml'."
            ) from exc
        return yaml.dump(self.to_dict(), sort_keys=False)


def _validate_string_list(val: Any, context: str) -> List[str]:
    """Validates that a field is a list/tuple of non-empty strings."""
    if val is None:
        return []
    if not isinstance(val, (list, tuple)):
        raise PolicyValidationError(f"{context} must be a list of strings, got {type(val).__name__}")
    result = []
    for idx, item in enumerate(val):
        if not isinstance(item, str) or not item.strip():
            raise PolicyValidationError(
                f"{context} item at index {idx} must be a non-empty string, got {item!r}"
            )
        result.append(item.strip())
    return result


def _validate_limit(val: Any, context: str) -> float:
    """Validates numeric limit fields such as max_quantity or max_amount."""
    if val is None or val == "inf" or val == float("inf"):
        return float("inf")
    if isinstance(val, (int, float)):
        if val < 0:
            raise PolicyValidationError(f"{context} cannot be negative, got {val}")
        return float(val)
    raise PolicyValidationError(f"{context} must be a non-negative number or 'inf', got {val!r}")


def _validate_argument_schema(val: Any, context: str) -> Optional[Dict[str, type]]:
    """Validates argument schema dictionary mapping parameter names to types."""
    if val is None:
        return None
    if not isinstance(val, dict):
        raise PolicyValidationError(f"{context} must be a dictionary, got {type(val).__name__}")

    schema: Dict[str, type] = {}
    for param, t_spec in val.items():
        if not isinstance(param, str) or not param.strip():
            raise PolicyValidationError(
                f"{context} parameter name must be a non-empty string, got {param!r}"
            )
        if isinstance(t_spec, type):
            schema[param.strip()] = t_spec
        elif isinstance(t_spec, str):
            t_lower = t_spec.strip().lower()
            if t_lower not in SUPPORTED_SCHEMA_TYPES:
                supported = ", ".join(sorted(SUPPORTED_SCHEMA_TYPES.keys()))
                raise PolicyValidationError(
                    f"{context} parameter '{param}' has unsupported schema type '{t_spec}'. "
                    f"Supported types: {supported}"
                )
            schema[param.strip()] = SUPPORTED_SCHEMA_TYPES[t_lower]
        else:
            raise PolicyValidationError(
                f"{context} parameter '{param}' type must be a Python type or supported type name string, "
                f"got {type(t_spec).__name__}"
            )
    return schema
