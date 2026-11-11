import pytest
from pathlib import Path
from unittest.mock import patch
import sys

from agentshield import (
    Shield,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    PolicyValidationError,
)
from agentshield.models import DecisionValue, Action


def test_policy_from_dict_complete():
    """Verifies that a complete policy configuration dictionary parses correctly."""
    data = {
        "agents": {
            "order_agent": {
                "name": "order_agent",
                "allowed_tools": ["create_order", "lookup_item"],
                "denied_tools": ["delete_item"],
                "allowed_destinations": ["api.store.internal"],
            },
            "analytics_agent": {
                "allowed_tools": ["query_metrics"],
                "allowed_destinations": ["metrics.internal"],
            },
        },
        "tools": {
            "create_order": {
                "max_quantity": 50,
                "max_amount": 5000.0,
                "required_permissions": ["orders:write"],
                "allowed_destinations": ["api.store.internal"],
                "argument_schema": {
                    "item_id": "str",
                    "quantity": "int",
                    "price": "float",
                    "is_gift": "bool",
                    "metadata": "dict",
                    "tags": "list",
                },
            },
            "query_metrics": {
                "max_quantity": "inf",
                "max_amount": float("inf"),
            },
        },
    }

    policy = PolicyConfiguration.from_dict(data)
    assert len(policy.agents) == 2
    assert "order_agent" in policy.agents
    assert "analytics_agent" in policy.agents

    order_agent = policy.agents["order_agent"]
    assert order_agent.name == "order_agent"
    assert order_agent.allowed_tools == ["create_order", "lookup_item"]
    assert order_agent.denied_tools == ["delete_item"]
    assert order_agent.allowed_destinations == ["api.store.internal"]

    analytics_agent = policy.agents["analytics_agent"]
    assert analytics_agent.name == "analytics_agent"
    assert analytics_agent.allowed_tools == ["query_metrics"]

    assert len(policy.tools) == 2
    create_order = policy.tools["create_order"]
    assert create_order.tool == "create_order"
    assert create_order.max_quantity == 50.0
    assert create_order.max_amount == 5000.0
    assert create_order.required_permissions == ["orders:write"]
    assert create_order.allowed_destinations == ["api.store.internal"]
    assert create_order.argument_schema == {
        "item_id": str,
        "quantity": int,
        "price": float,
        "is_gift": bool,
        "metadata": dict,
        "tags": list,
    }

    query_metrics = policy.tools["query_metrics"]
    assert query_metrics.max_quantity == float("inf")
    assert query_metrics.max_amount == float("inf")

    # Roundtrip serialization
    as_dict = policy.to_dict()
    reloaded = PolicyConfiguration.from_dict(as_dict)
    assert reloaded.compute_version_hash() == policy.compute_version_hash()


def test_policy_from_dict_list_format():
    """Verifies that agents and tools defined as lists are parsed properly."""
    data = {
        "agents": [
            {
                "name": "worker_agent",
                "allowed_tools": ["fetch_task", "submit_task"],
            }
        ],
        "tools": [
            {
                "tool": "fetch_task",
                "max_quantity": 5,
            },
            {
                "name": "submit_task",
                "required_permissions": ["tasks:submit"],
            },
        ],
    }

    policy = PolicyConfiguration.from_dict(data)
    assert "worker_agent" in policy.agents
    assert policy.agents["worker_agent"].allowed_tools == ["fetch_task", "submit_task"]
    assert "fetch_task" in policy.tools
    assert policy.tools["fetch_task"].max_quantity == 5.0
    assert "submit_task" in policy.tools
    assert policy.tools["submit_task"].required_permissions == ["tasks:submit"]


def test_policy_from_dict_empty_or_minimal():
    """Verifies that an empty dictionary produces an empty, valid PolicyConfiguration."""
    policy = PolicyConfiguration.from_dict({})
    assert policy.agents == {}
    assert policy.tools == {}
    assert len(policy.compute_version_hash()) == 16


def test_policy_validation_non_dict_root():
    """Rejects non-dictionary root configurations."""
    with pytest.raises(PolicyValidationError, match="must be a dictionary"):
        PolicyConfiguration.from_dict(["not", "a", "dict"])

    with pytest.raises(PolicyValidationError, match="must be a dictionary"):
        PolicyConfiguration.from_dict("invalid string")


def test_policy_validation_unknown_root_field():
    """Rejects unknown top-level fields to prevent typos."""
    with pytest.raises(PolicyValidationError, match="Unknown root field"):
        PolicyConfiguration.from_dict({"agent": {"foo": {}}})

    with pytest.raises(PolicyValidationError, match="Unknown root field"):
        PolicyConfiguration.from_dict({"rules": []})


def test_policy_validation_invalid_agents_structure():
    """Rejects invalid agents structure."""
    with pytest.raises(PolicyValidationError, match="'agents' must be a dictionary or list"):
        PolicyConfiguration.from_dict({"agents": "invalid"})

    with pytest.raises(PolicyValidationError, match="Agent key must be a non-empty string"):
        PolicyConfiguration.from_dict({"agents": {"": {}}})

    with pytest.raises(PolicyValidationError, match="must be a dictionary"):
        PolicyConfiguration.from_dict({"agents": {"my_agent": "not a dict"}})

    with pytest.raises(PolicyValidationError, match="contains unknown field"):
        PolicyConfiguration.from_dict({
            "agents": {
                "my_agent": {"name": "my_agent", "unrecognized_setting": 123}
            }
        })


def test_policy_validation_agent_contradictory_tools():
    """Rejects contradictory configurations where a tool is both allowed and denied."""
    with pytest.raises(PolicyValidationError, match="contradictory tools"):
        PolicyConfiguration.from_dict({
            "agents": {
                "bot": {
                    "allowed_tools": ["refund", "order"],
                    "denied_tools": ["refund"],
                }
            }
        })


def test_policy_validation_agent_field_types():
    """Rejects invalid field types inside agent configs."""
    with pytest.raises(PolicyValidationError, match="'allowed_tools' must be a list of strings"):
        PolicyConfiguration.from_dict({
            "agents": {"bot": {"allowed_tools": "not a list"}}
        })

    with pytest.raises(PolicyValidationError, match="must be a non-empty string"):
        PolicyConfiguration.from_dict({
            "agents": {"bot": {"allowed_tools": ["valid", ""]}}
        })


def test_policy_validation_invalid_tools_structure():
    """Rejects invalid tools structure."""
    with pytest.raises(PolicyValidationError, match="'tools' must be a dictionary or list"):
        PolicyConfiguration.from_dict({"tools": 12345})

    with pytest.raises(PolicyValidationError, match="Tool key must be a non-empty string"):
        PolicyConfiguration.from_dict({"tools": {"": {}}})

    with pytest.raises(PolicyValidationError, match="must be a dictionary"):
        PolicyConfiguration.from_dict({"tools": {"calc": "not a dict"}})

    with pytest.raises(PolicyValidationError, match="contains unknown field"):
        PolicyConfiguration.from_dict({
            "tools": {
                "calc": {"unknown_tool_field": True}
            }
        })


def test_policy_validation_tool_limits():
    """Rejects negative or non-numeric tool limits."""
    with pytest.raises(PolicyValidationError, match="cannot be negative"):
        PolicyConfiguration.from_dict({
            "tools": {"calc": {"max_quantity": -1}}
        })

    with pytest.raises(PolicyValidationError, match="must be a non-negative number or 'inf'"):
        PolicyConfiguration.from_dict({
            "tools": {"calc": {"max_amount": "invalid_amount"}}
        })


def test_policy_validation_argument_schema():
    """Rejects invalid argument schema specifications."""
    with pytest.raises(PolicyValidationError, match="'argument_schema' must be a dictionary"):
        PolicyConfiguration.from_dict({
            "tools": {"calc": {"argument_schema": "not a dict"}}
        })

    with pytest.raises(PolicyValidationError, match="unsupported schema type 'complex'"):
        PolicyConfiguration.from_dict({
            "tools": {"calc": {"argument_schema": {"val": "complex"}}}
        })

    with pytest.raises(PolicyValidationError, match="must be a Python type or supported type name string"):
        PolicyConfiguration.from_dict({
            "tools": {"calc": {"argument_schema": {"val": 12345}}}
        })


def test_policy_validation_list_format_duplicates():
    """Rejects duplicate names in list format."""
    with pytest.raises(PolicyValidationError, match="Duplicate agent definition"):
        PolicyConfiguration.from_dict({
            "agents": [
                {"name": "worker"},
                {"name": "worker"},
            ]
        })

    with pytest.raises(PolicyValidationError, match="Duplicate tool definition"):
        PolicyConfiguration.from_dict({
            "tools": [
                {"tool": "fetch"},
                {"tool": "fetch"},
            ]
        })


def test_from_yaml_without_pyyaml(monkeypatch):
    """Verifies clear, helpful ImportError when PyYAML is not available."""
    # Force ImportError for yaml
    with patch.dict(sys.modules, {"yaml": None}):
        with pytest.raises(ImportError) as exc_info:
            PolicyConfiguration.from_yaml("agents: {}")

        msg = str(exc_info.value)
        assert "PyYAML is required" in msg
        assert "pip install agentshield[yaml]" in msg or "pip install pyyaml" in msg


def test_from_yaml_mocked_execution(tmp_path):
    """Verifies from_yaml, from_yaml_file, and to_yaml execution paths using a mocked yaml module."""
    import types
    import json

    fake_yaml = types.ModuleType("yaml")
    sample_dict = {
        "agents": {
            "mock_agent": {
                "name": "mock_agent",
                "allowed_tools": ["search"],
            }
        },
        "tools": {
            "search": {
                "max_quantity": 10,
            }
        }
    }
    fake_yaml.safe_load = lambda s: sample_dict
    fake_yaml.dump = lambda d, **kw: json.dumps(d)
    fake_yaml.YAMLError = Exception

    with patch.dict(sys.modules, {"yaml": fake_yaml}):
        # 1. From YAML string
        p1 = PolicyConfiguration.from_yaml("dummy yaml string")
        assert "mock_agent" in p1.agents
        assert "search" in p1.tools

        # 2. From file Path
        yaml_file = tmp_path / "mock_policy.yaml"
        yaml_file.write_text("agents:\n  mock_agent: {}\n", encoding="utf-8")
        p2 = PolicyConfiguration.from_yaml(yaml_file)
        assert p2.compute_version_hash() == p1.compute_version_hash()

        # 3. From file path string
        p3 = PolicyConfiguration.from_yaml_file(str(yaml_file))
        assert p3.compute_version_hash() == p1.compute_version_hash()

        # 4. to_yaml serialization
        serialized = p1.to_yaml()
        assert "mock_agent" in serialized



def test_from_yaml_and_to_yaml_with_pyyaml(tmp_path):
    """Verifies YAML parsing and serialization when PyYAML is installed/available."""
    pytest.importorskip("yaml")

    yaml_text = """
version: "1"
agents:
  assistant:
    allowed_tools:
      - search
      - summarize
    allowed_destinations:
      - search.internal.net
tools:
  search:
    max_quantity: 10
    required_permissions:
      - search:read
    allowed_destinations:
      - search.internal.net
    argument_schema:
      query: str
      limit: int
"""

    policy = PolicyConfiguration.from_yaml(yaml_text)
    assert "assistant" in policy.agents
    assert policy.agents["assistant"].allowed_tools == ["search", "summarize"]
    assert policy.tools["search"].max_quantity == 10.0
    assert policy.tools["search"].argument_schema == {"query": str, "limit": int}

    # Test file path loading
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(yaml_text, encoding="utf-8")

    from_path = PolicyConfiguration.from_yaml(policy_file)
    assert from_path.compute_version_hash() == policy.compute_version_hash()

    from_file = PolicyConfiguration.from_yaml_file(str(policy_file))
    assert from_file.compute_version_hash() == policy.compute_version_hash()

    # Test to_yaml serialization
    exported_yaml = policy.to_yaml()
    assert "assistant" in exported_yaml
    assert "search" in exported_yaml

    reimported = PolicyConfiguration.from_yaml(exported_yaml)
    assert reimported.compute_version_hash() == policy.compute_version_hash()


def test_shield_constructor_with_declarative_policy():
    """Verifies Shield initialization directly accepting a PolicyConfiguration or dict."""
    policy = PolicyConfiguration.from_dict({
        "agents": {
            "custom_agent": {
                "allowed_tools": ["custom_tool"],
            }
        },
        "tools": {
            "custom_tool": {
                "max_amount": 100,
            }
        }
    })

    # 1. With PolicyConfiguration instance
    shield1 = Shield(policy=policy)
    assert "custom_agent" in shield1.policy_engine.config.agents
    assert "custom_tool" in shield1.policy_engine.known_tools

    # 2. With dictionary
    shield2 = Shield(policy={
        "agents": {
            "dict_agent": {"allowed_tools": ["dict_tool"]}
        },
        "tools": {
            "dict_tool": {"max_amount": 50}
        }
    })
    assert "dict_agent" in shield2.policy_engine.config.agents
    assert "dict_tool" in shield2.policy_engine.known_tools

    # 3. Invalid policy type raises TypeError
    with pytest.raises(TypeError, match="policy must be a PolicyConfiguration or dict"):
        Shield(policy=["invalid"])


def test_shield_load_policy_method():
    """Verifies dynamic policy loading onto an existing Shield instance."""
    shield = Shield()

    # Initial default policy has shopping_agent
    assert "shopping_agent" in shield.policy_engine.config.agents

    # Load new declarative policy from dict
    shield.load_policy({
        "agents": {
            "finance_bot": {
                "allowed_tools": ["transfer_funds"],
                "allowed_destinations": ["bank.internal"],
            }
        },
        "tools": {
            "transfer_funds": {
                "max_amount": 5000,
                "required_permissions": ["finance:transfer"],
            }
        }
    })

    assert "finance_bot" in shield.policy_engine.config.agents
    assert "shopping_agent" not in shield.policy_engine.config.agents
    assert "transfer_funds" in shield.policy_engine.known_tools


def test_shield_authorization_enforcement_with_declarative_policy():
    """Verifies that all deterministic security rules enforce correctly on declarative policies."""
    policy_dict = {
        "agents": {
            "checkout_agent": {
                "allowed_tools": ["charge_card", "get_status"],
                "denied_tools": ["refund_card"],
                "allowed_destinations": ["payments.secure.internal"],
            }
        },
        "tools": {
            "charge_card": {
                "max_quantity": 5,
                "max_amount": 1000.0,
                "required_permissions": ["payment:charge"],
                "allowed_destinations": ["payments.secure.internal"],
                "argument_schema": {
                    "card_id": "str",
                    "amount": "float",
                    "quantity": "int",
                },
            },
            "get_status": {
                "max_quantity": "inf",
            },
            "refund_card": {
                "max_amount": 5000.0,
            },
        }
    }

    shield = Shield(policy=policy_dict)
    called = []
    shield.registry.register("charge_card", lambda args: called.append(args) or {"charged": True})

    # 1. Legitimate action with valid arguments, permissions, and destination -> ALLOW
    legit_action = Action(
        agent="checkout_agent",
        tool="charge_card",
        arguments={
            "card_id": "tok_12345",
            "amount": 250.0,
            "quantity": 1,
            "destination": "payments.secure.internal",
        }
    )
    dec_allow = shield.authorize(
        agent=legit_action.agent,
        tool=legit_action.tool,
        arguments=dict(legit_action.arguments),
        permissions=["payment:charge"],
    )
    assert dec_allow.decision == DecisionValue.ALLOW
    assert dec_allow.allowed is True

    # Execution works exactly once per call
    exec_res = shield.execute(
        agent=legit_action.agent,
        tool=legit_action.tool,
        arguments=dict(legit_action.arguments),
        permissions=["payment:charge"],
    )
    assert exec_res.execution_status.value == "executed"
    assert exec_res.tool_result == {"charged": True}
    assert len(called) == 1

    # 2. Unknown agent -> BLOCK
    dec_unknown_agent = shield.authorize(
        agent="fraud_bot",
        tool="charge_card",
        arguments={"card_id": "tok_1", "amount": 10.0, "quantity": 1},
        permissions=["payment:charge"],
    )
    assert dec_unknown_agent.decision == DecisionValue.BLOCK
    assert "Unknown agent: fraud_bot" in dec_unknown_agent.reasons[0]

    # 3. Unknown tool -> BLOCK
    dec_unknown_tool = shield.authorize(
        agent="checkout_agent",
        tool="wire_transfer",
        arguments={},
    )
    assert dec_unknown_tool.decision == DecisionValue.BLOCK
    assert "Unknown tool" in dec_unknown_tool.reasons[0]

    # 4. Explicitly denied tool -> BLOCK
    dec_denied_tool = shield.authorize(
        agent="checkout_agent",
        tool="refund_card",
        arguments={"amount": 100.0},
    )
    assert dec_denied_tool.decision == DecisionValue.BLOCK
    assert "Tool refund_card is explicitly denied" in dec_denied_tool.reasons[0]

    # 5. Missing required permission -> BLOCK
    dec_missing_perm = shield.authorize(
        agent="checkout_agent",
        tool="charge_card",
        arguments={"card_id": "tok_1", "amount": 100.0, "quantity": 1},
        permissions=[],  # missing 'payment:charge'
    )
    assert dec_missing_perm.decision == DecisionValue.BLOCK
    assert any("Missing required permission" in r for r in dec_missing_perm.reasons)

    # 6. Destination outside allowlist -> BLOCK (exact hostname matching, no substring bypass)
    dec_bad_dest = shield.authorize(
        agent="checkout_agent",
        tool="charge_card",
        arguments={
            "card_id": "tok_1",
            "amount": 100.0,
            "quantity": 1,
            "destination": "evil-payments.secure.internal",
        },
        permissions=["payment:charge"],
    )
    assert dec_bad_dest.decision == DecisionValue.BLOCK
    assert any("Destination hostname" in r for r in dec_bad_dest.reasons)

    # 7. Argument schema mismatch -> BLOCK
    dec_bad_schema = shield.authorize(
        agent="checkout_agent",
        tool="charge_card",
        arguments={
            "card_id": 12345,  # int instead of str
            "amount": 100.0,
            "quantity": 1,
        },
        permissions=["payment:charge"],
    )
    assert dec_bad_schema.decision == DecisionValue.BLOCK
    assert any("Argument 'card_id' must be of type str" in r for r in dec_bad_schema.reasons)

    # 8. Exceeding max_amount limit -> BLOCK
    dec_exceed_amount = shield.authorize(
        agent="checkout_agent",
        tool="charge_card",
        arguments={"card_id": "tok_1", "amount": 25000.0, "quantity": 1},
        permissions=["payment:charge"],
    )
    assert dec_exceed_amount.decision == DecisionValue.BLOCK
    assert any("exceeds maximum of 1000.0" in r for r in dec_exceed_amount.reasons)

    # 9. Exceeding max_quantity limit -> BLOCK
    dec_exceed_qty = shield.authorize(
        agent="checkout_agent",
        tool="charge_card",
        arguments={"card_id": "tok_1", "amount": 50.0, "quantity": 99},
        permissions=["payment:charge"],
    )
    assert dec_exceed_qty.decision == DecisionValue.BLOCK
    assert any("exceeds maximum of 5" in r for r in dec_exceed_qty.reasons)
