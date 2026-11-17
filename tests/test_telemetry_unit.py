"""
Unit tests for AgentShield Telemetry SDK components:
- Configuration and key masking
- Secret redaction
- Queue management and standalone safety
- Retry logic and error handling
"""

import logging
import os
import time
import urllib.error
from unittest.mock import patch, MagicMock

import pytest

from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.telemetry import TelemetryConfig, TelemetryExporter, TelemetryEvent


def test_telemetry_config_key_masking():
    """Verify that TelemetryConfig never prints or leaks raw API keys."""
    raw_key = "sk_tenant_prod_secret_123456789"
    config = TelemetryConfig(
        api_url="https://api.agentshield.example.com",
        api_key=raw_key,
        tenant_id="tenant-prod",
    )
    repr_str = repr(config)
    str_str = str(config)

    assert raw_key not in repr_str, "Raw API key must not appear in TelemetryConfig __repr__"
    assert raw_key not in str_str, "Raw API key must not appear in TelemetryConfig __str__"
    assert "sk_...***" in repr_str
    assert config.is_configured is True


def test_telemetry_config_from_env():
    """Verify loading config from standard environment variables."""
    with patch.dict(os.environ, {
        "AGENTSHIELD_API_URL": "http://127.0.0.1:8000",
        "AGENTSHIELD_API_KEY": "test-key-env-999",
        "AGENTSHIELD_TENANT_ID": "env-tenant-1",
        "AGENTSHIELD_TELEMETRY_ENABLED": "true",
        "AGENTSHIELD_TELEMETRY_BATCH_SIZE": "15",
        "AGENTSHIELD_TELEMETRY_TIMEOUT": "3.5",
    }):
        cfg = TelemetryConfig.from_env()
        assert cfg.api_url == "http://127.0.0.1:8000"
        assert cfg.api_key == "test-key-env-999"
        assert cfg.tenant_id == "env-tenant-1"
        assert cfg.batch_size == 15
        assert cfg.timeout_seconds == 3.5
        assert cfg.is_configured is True


def test_telemetry_unconfigured_safety():
    """Verify that an unconfigured exporter is a complete no-op with zero network threads."""
    cfg = TelemetryConfig()  # No api_url or api_key
    assert cfg.is_configured is False

    exporter = TelemetryExporter(cfg)
    assert exporter._worker_thread is None

    # Recording should return False immediately
    res = exporter.record(TelemetryEvent())
    assert res is False
    assert exporter._queue.empty()

    # Flush and close should succeed immediately without error
    assert exporter.flush() is True
    exporter.close()


def test_telemetry_event_secret_redaction():
    """Verify that TelemetryEvent automatically scrubs sensitive arguments."""
    event = TelemetryEvent(
        agent="test-agent",
        tool="connect_database",
        arguments={
            "api_key": "super_secret_token_12345",
            "db_password": "my_db_password",
            "host": "db.internal.example.com",
            "query": "SELECT * FROM users WHERE token = 'bearer abcdef123456789'",
        },
        error="Failed with auth token bearer xyz987654321",
    )
    d = event.to_dict()

    # Arguments must be redacted
    assert d["arguments"]["api_key"] == "[REDACTED]"
    assert d["arguments"]["db_password"] == "[REDACTED]"
    assert d["arguments"]["host"] == "db.internal.example.com"
    assert "abcdef123456789" not in d["arguments"]["query"]
    assert "xyz987654321" not in d["error"]


def test_telemetry_exporter_queue_limits():
    """Verify that queue limits prevent unbounded memory allocation under load."""
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:9999",
        api_key="mock-key",
        max_queue_size=5,
        flush_interval_seconds=0.01,
        spool_enabled=False,
    )
    exporter = TelemetryExporter(cfg)
    try:
        # Stop the worker thread so items stay in queue
        exporter._stop_event.set()
        if exporter._worker_thread:
            exporter._worker_thread.join(timeout=2.0)

        # Fill queue to maximum
        for i in range(5):
            ok = exporter.record(TelemetryEvent(agent=f"agent-{i}"))
            assert ok is True

        # 6th item should be dropped cleanly without raising an exception
        dropped = exporter.record(TelemetryEvent(agent="agent-overflow"))
        assert dropped is False
        assert exporter._queue.full()
    finally:
        # Drain mock queue items and close to ensure clean process termination
        while not exporter._queue.empty():
            exporter._queue.get_nowait()
        exporter.close()


def test_telemetry_exporter_retry_behavior():
    """Verify retry with exponential backoff on transient 503 and fast fail on 401."""
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:8000",
        api_key="secret-key-123",
        max_retries=2,
        retry_backoff_base=0.01,
    )
    exporter = TelemetryExporter(cfg)
    exporter.close()  # stop background thread to test _send_http_with_retries directly

    data = b'{"events": []}'
    headers = {"Content-Type": "application/json"}

    # 1. 503 Service Unavailable -> should retry max_retries times
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:8000/api/v1/telemetry/events",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None,
        )
        success = exporter._send_http_with_retries("http://127.0.0.1:8000/api/v1/telemetry/events", data, headers)
        assert success is False
        assert mock_urlopen.call_count == 3  # Initial + 2 retries

    # 2. 401 Unauthorized -> should fail fast without retrying
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:8000/api/v1/telemetry/events",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None,
        )
        success = exporter._send_http_with_retries("http://127.0.0.1:8000/api/v1/telemetry/events", data, headers)
        assert success is False
        assert mock_urlopen.call_count == 1  # No retries on 401


def test_telemetry_exporter_close_unregisters_atexit():
    """Regression test: verify that close() unregisters exporter from atexit handlers."""
    import atexit
    cfg = TelemetryConfig(
        api_url="http://127.0.0.1:8000",
        api_key="mock-key",
    )
    with patch("atexit.unregister") as mock_unregister:
        exporter = TelemetryExporter(cfg)
        assert exporter._closed is False
        exporter.close()
        assert exporter._closed is True
        mock_unregister.assert_called_once_with(exporter.close)

