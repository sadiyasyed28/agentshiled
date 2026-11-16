"""
Acceptance test for Milestone 2: SDK-to-Cloud Telemetry.

Runs a separate, independent Python process using the AgentShield SDK,
executes actual protected tools that trigger ALLOW and BLOCK decisions,
transmits telemetry over HTTP to the hosted AgentShield backend,
and verifies that the events are stored under the correct tenant
and faithfully returned by the dashboard API.
"""

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import json
import pytest
import uvicorn

from agentshield.api.app import create_app


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_server(tmp_path):
    port = find_free_port()
    audit_db = str(tmp_path / "acceptance_audit.db")
    events_db = str(tmp_path / "acceptance_events.db")

    tenant_keys = {
        "customer-tenant": "sk_customer_secret_key_8888",
        "isolated-tenant": "sk_isolated_secret_key_9999",
    }
    app = create_app(
        admin_api_key="master-admin-key",
        tenant_api_keys=tenant_keys,
        audit_db_path=audit_db,
        events_db_path=events_db,
        read_only=False,
    )

    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to accept connections
    max_wait = 10.0
    start = time.perf_counter()
    server_ready = False
    while time.perf_counter() - start < max_wait:
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/health")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    server_ready = True
                    break
        except Exception:
            time.sleep(0.1)

    assert server_ready, f"Hosted server failed to bind and start on 127.0.0.1:{port}"

    yield f"http://127.0.0.1:{port}", "sk_customer_secret_key_8888", "sk_isolated_secret_key_9999"

    server.should_exit = True
    thread.join(timeout=3.0)


def test_sdk_to_cloud_telemetry_acceptance(running_server):
    """
    Acceptance Test:
    1. Spawns a separate external Python process.
    2. Uses AgentShield SDK with remote telemetry enabled.
    3. Executes protected tool calls (ALLOW and BLOCK).
    4. Automatically transmits telemetry to the hosted dashboard API.
    5. Verifies events and metrics on the dashboard API for the correct tenant.
    6. Verifies tenant isolation against other tenants.
    """
    server_url, customer_key, isolated_key = running_server

    external_agent_script = f"""
import sys
from agentshield import Shield, ToolBlockedError
from agentshield.policy import PolicyConfiguration, AgentConfig, ToolRule

# Configure policy
policy = PolicyConfiguration(
    agents={{
        "support-agent": AgentConfig(
            name="support-agent",
            allowed_tools=["read_ticket_data"],
            denied_tools=["drop_table", "refund_user"]
        )
    }},
    tools={{
        "read_ticket_data": ToolRule(tool="read_ticket_data"),
        "refund_user": ToolRule(tool="refund_user", required_permissions=["finance"])
    }}
)

# SDK automatically discovers AGENTSHIELD_API_URL and AGENTSHIELD_API_KEY from env
shield = Shield(policy=policy, tenant_id="customer-tenant")

# 1. Execute an allowed tool
@shield.protect_tool(name="read_ticket_data", agent="support-agent")
def read_ticket_data(ticket_id: str):
    return {{"ticket_id": ticket_id, "priority": "high"}}

res = read_ticket_data("TCK-9901")
assert res["ticket_id"] == "TCK-9901"

# 2. Execute a blocked tool (policy denies refund_user to support-agent)
@shield.protect_tool(name="refund_user", agent="support-agent")
def refund_user(amount: float):
    return "refunded"

blocked_caught = False
try:
    refund_user(150.0)
except ToolBlockedError as e:
    blocked_caught = True

assert blocked_caught, "Expected ToolBlockedError on denied tool"

# Flush telemetry and close cleanly
flushed = shield.flush_telemetry(timeout=5.0)
shield.close()
assert flushed, "Telemetry exporter flush failed"
sys.exit(0)
"""

    sub_env = dict(os.environ)
    sub_env["AGENTSHIELD_API_URL"] = server_url
    sub_env["AGENTSHIELD_API_KEY"] = customer_key
    sub_env["AGENTSHIELD_TENANT_ID"] = "customer-tenant"
    sub_env["PYTHONPATH"] = "src"

    # Run external Python subprocess
    proc = subprocess.run(
        [sys.executable, "-c", external_agent_script],
        env=sub_env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    if proc.returncode != 0:
        print("Subprocess STDOUT:", proc.stdout)
        print("Subprocess STDERR:", proc.stderr)
    assert proc.returncode == 0, f"External SDK process failed with code {proc.returncode}"

    # Verify Dashboard API for customer-tenant: GET /api/events
    events_req = urllib.request.Request(
        f"{server_url}/api/events",
        headers={"X-API-Key": customer_key},
    )
    with urllib.request.urlopen(events_req, timeout=5.0) as resp:
        assert resp.status == 200
        events_payload = json.loads(resp.read().decode("utf-8"))

    events = events_payload["events"]
    assert len(events) == 4, f"Expected 4 telemetry events (decisions and outcomes), got {len(events)}"

    tools = {e["tool"] for e in events}
    assert "read_ticket_data" in tools
    assert "refund_user" in tools

    decisions = {e["decision"] for e in events}
    assert "ALLOW" in decisions
    assert "BLOCK" in decisions

    statuses = {e["execution_status"] for e in events}
    assert "executed" in statuses
    assert "not_executed" in statuses

    # Verify Dashboard API for customer-tenant: GET /api/overview
    overview_req = urllib.request.Request(
        f"{server_url}/api/overview",
        headers={"X-API-Key": customer_key},
    )
    with urllib.request.urlopen(overview_req, timeout=5.0) as resp:
        assert resp.status == 200
        ov_payload = json.loads(resp.read().decode("utf-8"))

    assert ov_payload["total_evaluated"] == 4
    assert ov_payload["allow_count"] == 2
    assert ov_payload["block_count"] == 2

    # Verify Tenant Isolation: isolated-tenant querying same server sees 0 events
    isolated_events_req = urllib.request.Request(
        f"{server_url}/api/events",
        headers={"X-API-Key": isolated_key},
    )
    with urllib.request.urlopen(isolated_events_req, timeout=5.0) as resp:
        assert resp.status == 200
        isolated_events = json.loads(resp.read().decode("utf-8"))
        assert isolated_events["total"] == 0
        assert len(isolated_events["events"]) == 0

