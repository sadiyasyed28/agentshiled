"""
Telemetry configuration for AgentShield SDK-to-Cloud communication.
"""

from dataclasses import dataclass, field
import os
from typing import Optional, Callable, Any


@dataclass
class TelemetryConfig:
    """Configuration for external AgentShield SDK telemetry streaming."""

    api_url: Optional[str] = None
    api_key: Optional[str] = None
    tenant_id: Optional[str] = None
    batch_size: int = 20
    flush_interval_seconds: float = 1.0
    max_queue_size: int = 1000
    timeout_seconds: float = 5.0
    max_retries: int = 3
    retry_backoff_base: float = 0.5
    enabled: bool = True
    spool_enabled: bool = True
    spool_dir: Optional[str] = None
    max_spool_size: int = 5000
    on_overflow: Optional[Callable[[Any], None]] = None

    @classmethod
    def from_env(cls) -> "TelemetryConfig":
        """Loads telemetry configuration from standard environment variables."""
        api_url = os.environ.get("AGENTSHIELD_API_URL", "").strip() or None
        api_key = os.environ.get("AGENTSHIELD_API_KEY", "").strip() or None
        tenant_id = os.environ.get("AGENTSHIELD_TENANT_ID", "").strip() or None

        raw_enabled = os.environ.get("AGENTSHIELD_TELEMETRY_ENABLED", "true").strip().lower()
        enabled = raw_enabled not in ("0", "false", "no", "off")

        raw_batch = os.environ.get("AGENTSHIELD_TELEMETRY_BATCH_SIZE", "").strip()
        batch_size = int(raw_batch) if raw_batch.isdigit() else 20

        raw_timeout = os.environ.get("AGENTSHIELD_TELEMETRY_TIMEOUT", "").strip()
        timeout = float(raw_timeout) if raw_timeout else 5.0

        raw_spool = os.environ.get("AGENTSHIELD_TELEMETRY_SPOOL_ENABLED", "true").strip().lower()
        spool_enabled = raw_spool not in ("0", "false", "no", "off")
        spool_dir = os.environ.get("AGENTSHIELD_TELEMETRY_SPOOL_DIR", "").strip() or None

        raw_spool_size = os.environ.get("AGENTSHIELD_TELEMETRY_MAX_SPOOL_SIZE", "").strip()
        max_spool_size = int(raw_spool_size) if raw_spool_size.isdigit() else 5000

        return cls(
            api_url=api_url,
            api_key=api_key,
            tenant_id=tenant_id,
            enabled=enabled,
            batch_size=batch_size,
            timeout_seconds=timeout,
            spool_enabled=spool_enabled,
            spool_dir=spool_dir,
            max_spool_size=max_spool_size,
        )

    @property
    def is_configured(self) -> bool:
        """Returns True if telemetry has valid URL, API key, and is enabled."""
        return bool(self.enabled and self.api_url and self.api_key)

    def __repr__(self) -> str:
        """Prevents leaking raw API keys in logs, representations, or stack traces."""
        if self.api_key:
            masked = f"{self.api_key[:3]}...***" if len(self.api_key) > 6 else "***"
        else:
            masked = None

        return (
            f"TelemetryConfig(api_url={self.api_url!r}, api_key={masked!r}, "
            f"tenant_id={self.tenant_id!r}, enabled={self.enabled}, "
            f"batch_size={self.batch_size}, timeout_seconds={self.timeout_seconds})"
        )

