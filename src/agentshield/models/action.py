from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import unicodedata
from urllib.parse import urlparse, urlunparse

class FrozenDict(dict):
    """An immutable dictionary that prevents modification at runtime."""

    def __setitem__(self, key: Any, value: Any) -> None:
        raise TypeError("FrozenDict is immutable and does not support item assignment")

    def __delitem__(self, key: Any) -> None:
        raise TypeError("FrozenDict is immutable and does not support item deletion")

    def clear(self) -> None:
        raise TypeError("FrozenDict is immutable and does not support clear")

    def pop(self, *args: Any, **kwargs: Any) -> Any:
        raise TypeError("FrozenDict is immutable and does not support pop")

    def popitem(self) -> Any:
        raise TypeError("FrozenDict is immutable and does not support popitem")

    def setdefault(self, key: Any, default: Any = None) -> Any:
        raise TypeError("FrozenDict is immutable and does not support setdefault")

    def update(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("FrozenDict is immutable and does not support update")

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: Optional[Dict[int, Any]] = None) -> "FrozenDict":
        return self


class FrozenList(list):
    """An immutable list that prevents modification at runtime."""

    def __setitem__(self, index: Any, value: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support item assignment")

    def __delitem__(self, index: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support item deletion")

    def append(self, value: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support append")

    def extend(self, values: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support extend")

    def insert(self, index: int, value: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support insert")

    def remove(self, value: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support remove")

    def pop(self, *args: Any) -> Any:
        raise TypeError("FrozenList is immutable and does not support pop")

    def clear(self) -> None:
        raise TypeError("FrozenList is immutable and does not support clear")

    def sort(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("FrozenList is immutable and does not support sort")

    def reverse(self) -> None:
        raise TypeError("FrozenList is immutable and does not support reverse")

    def __iadd__(self, values: Any) -> "FrozenList":
        raise TypeError("FrozenList is immutable and does not support in-place addition")

    def __copy__(self) -> "FrozenList":
        return self

    def __deepcopy__(self, memo: Optional[Dict[int, Any]] = None) -> "FrozenList":
        return self


def normalize_string(val: str, field_name: str = "") -> str:
    """Normalizes string inputs with canonical Unicode NFC form and cleans URL/host destinations."""
    normalized = unicodedata.normalize("NFC", val)
    if field_name.lower() in ("url", "destination", "host", "domain"):
        cleaned = normalized.strip()
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            norm_scheme = parsed.scheme.lower()
            norm_netloc = parsed.netloc.lower()
            return urlunparse((norm_scheme, norm_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        elif cleaned.startswith("//"):
            parsed = urlparse(cleaned)
            return f"//{parsed.netloc.lower()}{parsed.path}"
        return cleaned
    return normalized


def _normalize_field_value(v: Any, expected_type: Optional[type] = None, field_name: str = "") -> Any:
    """Recursively normalizes and deep-freezes a single value."""
    if isinstance(v, str):
        return normalize_string(v, field_name=field_name)
    elif isinstance(v, (dict, Mapping)):
        return normalize_and_freeze(v, schema=None)
    elif isinstance(v, (list, tuple)):
        return FrozenList([_normalize_field_value(item, field_name=field_name) for item in v])
    elif isinstance(v, set):
        return frozenset(_normalize_field_value(item, field_name=field_name) for item in v)
    else:
        return v


def normalize_and_freeze(
    arguments: Any,
    schema: Optional[Dict[str, type]] = None
) -> FrozenDict:
    """Normalizes arguments using schema awareness and returns a deep-frozen immutable mapping."""
    if not isinstance(arguments, (dict, Mapping)):
        raise TypeError("arguments must be a dictionary")

    schema = schema or {}
    normalized_dict = {}

    for k, v in arguments.items():
        key_str = unicodedata.normalize("NFC", str(k)).strip()
        expected_type = schema.get(key_str) or schema.get(str(k))
        normalized_dict[key_str] = _normalize_field_value(v, expected_type=expected_type, field_name=key_str)

    return FrozenDict(normalized_dict)


def unfreeze_value(val: Any) -> Any:
    """Recursively converts FrozenDict and FrozenList back into standard mutable dicts and lists.
    Used by the safe execution adapter to supply tool callables with a defensive copy.
    """
    if isinstance(val, (FrozenDict, dict)):
        return {str(k): unfreeze_value(v) for k, v in val.items()}
    elif isinstance(val, (FrozenList, list, tuple)):
        return [unfreeze_value(item) for item in val]
    return val


@dataclass
class Action:
    agent: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not isinstance(self.agent, str) or not self.agent.strip():
            raise ValueError("agent must be a non-empty string")
        if not isinstance(self.tool, str) or not self.tool.strip():
            raise ValueError("tool must be a non-empty string")
        if not isinstance(self.arguments, dict):
            raise TypeError("arguments must be a dictionary")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be a dictionary")

        if not isinstance(self.arguments, FrozenDict):
            self.arguments = normalize_and_freeze(self.arguments)
        if not isinstance(self.metadata, FrozenDict):
            self.metadata = normalize_and_freeze(self.metadata)
