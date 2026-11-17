"""
Remote telemetry exporter for sending AgentShield security events to the hosted platform.
"""

import atexit
from dataclasses import dataclass, field, asdict, fields
from datetime import datetime, timezone
import json
import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
import uuid

from agentshield.audit.store import redact_sensitive_data
from agentshield.models import Decision, DecisionValue, RiskLevel
from agentshield.telemetry.config import TelemetryConfig
from agentshield.telemetry.spool import TelemetrySpool

logger = logging.getLogger("agentshield.telemetry")


@dataclass
class TelemetryEvent:
    """Standard serialized payload for a remote telemetry event."""

    event_id: str = field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:12]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent: str = "unknown"
    tool: str = "unknown"
    decision: str = "BLOCK"
    allowed: bool = False
    reasons: List[str] = field(default_factory=list)
    rules_triggered: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    severity: str = "LOW"
    execution_status: str = "not_executed"
    arguments: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    policy_version_hash: Optional[str] = None
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_type: str = "authorization_decision"

    def to_dict(self) -> Dict[str, Any]:
        """Returns clean dictionary with guaranteed sensitive data redaction."""
        d = asdict(self)
        d["arguments"] = redact_sensitive_data(d.get("arguments") or {})
        if d.get("error"):
            d["error"] = redact_sensitive_data(d["error"])
        if d.get("reasons"):
            d["reasons"] = [redact_sensitive_data(r) for r in d["reasons"]]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TelemetryEvent":
        """Reconstructs TelemetryEvent from dictionary safely ignoring unknown fields."""
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)


class TelemetryExporter:
    """
    Background batch telemetry exporter sending agent decisions and security events
    to the hosted AgentShield backend via secure HTTP ingestion with local disk spooling.
    """

    def __init__(self, config: Optional[TelemetryConfig] = None):
        self.config = config or TelemetryConfig.from_env()
        self._queue: queue.Queue = queue.Queue(maxsize=self.config.max_queue_size)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._closed = False

        self._stats = {
            "enqueued": 0,
            "sent": 0,
            "dropped": 0,
            "spooled": 0,
            "replayed": 0,
            "retry_exhausted": 0,
        }
        self._last_successful_transmission: Optional[str] = None
        self._last_transmission_error: Optional[str] = None

        self.spool: Optional[TelemetrySpool] = (
            TelemetrySpool(
                spool_dir=self.config.spool_dir,
                max_size=self.config.max_spool_size,
                tenant_id=self.config.tenant_id,
            )
            if self.config.spool_enabled
            else None
        )

        if self.config.is_configured:
            self._start_worker()
            atexit.register(self.close)

    @property
    def stats(self) -> Dict[str, Any]:
        """Returns real-time telemetry metrics."""
        with self._lock:
            s = dict(self._stats)
            s["last_successful_transmission"] = self._last_successful_transmission
            s["last_transmission_error"] = self._last_transmission_error
        s["pending_queue"] = self._queue.qsize()
        s["pending_spool"] = self.spool.count() if self.spool else 0
        return s

    @property
    def last_successful_transmission(self) -> Optional[str]:
        """ISO timestamp of last successful transmission, or None."""
        with self._lock:
            return self._last_successful_transmission

    @property
    def last_transmission_error(self) -> Optional[str]:
        """Last transmission error message, or None."""
        with self._lock:
            return self._last_transmission_error

    @property
    def dropped_count(self) -> int:
        """Returns count of dropped events due to queue/spool exhaustion."""
        with self._lock:
            return self._stats["dropped"]

    @property
    def spooled_count(self) -> int:
        """Returns count of currently spooled events awaiting replay."""
        return self.spool.count() if self.spool else 0

    def _start_worker(self) -> None:
        """Starts background exporter worker thread if configured."""
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(
                    target=self._worker_loop,
                    name="agentshield-telemetry-exporter",
                    daemon=True,
                )
                self._worker_thread.start()

    def record(self, event: TelemetryEvent) -> bool:
        """
        Enqueues a telemetry event for background batch transmission.
        If in-memory queue is full, spools to persistent disk.
        If spool is also full or disabled, increments dropped counter and calls on_overflow.
        """
        if not self.config.is_configured or self._closed:
            return False

        try:
            self._queue.put_nowait(event)
            with self._lock:
                self._stats["enqueued"] += 1
            return True
        except queue.Full:
            # In-memory queue is full: spill over to local disk spool
            if self.spool:
                spooled = self.spool.spool_events([event])
                if spooled > 0:
                    with self._lock:
                        self._stats["spooled"] += 1
                    logger.warning(
                        "AgentShield telemetry queue full (%d events); spooled event %s to persistent disk",
                        self.config.max_queue_size,
                        event.event_id,
                    )
                    return True

            with self._lock:
                self._stats["dropped"] += 1
            logger.warning(
                "AgentShield telemetry queue and spool are full; dropping event %s",
                event.event_id,
            )
            if self.config.on_overflow:
                try:
                    self.config.on_overflow(event)
                except Exception:
                    pass
            return False

    def record_decision(
        self,
        decision: Decision,
        arguments: Optional[Any] = None,
        execution_status: str = "not_executed",
        error: Optional[str] = None,
        policy_version_hash: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        event_type: str = "authorization_decision",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Constructs and enqueues a TelemetryEvent from an AgentShield Decision."""
        if not self.config.is_configured or self._closed:
            return False

        raw_args = arguments if isinstance(arguments, dict) else ({"value": arguments} if arguments is not None else {})
        clean_args = redact_sensitive_data(raw_args)

        dec_str = decision.decision.value if hasattr(decision.decision, "value") else str(decision.decision)
        sev_str = decision.severity.value if hasattr(decision.severity, "value") else str(decision.severity)

        rules = [r.split(":")[0].strip() for r in decision.reasons if ":" in r]
        corr_id = correlation_id or getattr(decision, "correlation_id", None)
        trc_id = trace_id or getattr(decision, "trace_id", None)

        event = TelemetryEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=decision.agent,
            tool=decision.tool,
            decision=dec_str,
            allowed=bool(decision.allowed),
            reasons=list(decision.reasons),
            rules_triggered=rules,
            risk_score=float(decision.risk_score),
            severity=sev_str,
            execution_status=execution_status,
            arguments=clean_args,
            error=str(error) if error else None,
            policy_version_hash=policy_version_hash,
            correlation_id=corr_id,
            trace_id=trc_id,
            metadata=metadata or {},
            event_type=event_type,
        )
        return self.record(event)

    def record_event(
        self,
        agent: str,
        tool: str,
        event_type: str,
        severity: str,
        decision: str,
        allowed: bool,
        reasons: List[str],
        risk_score: float = 0.0,
        execution_status: str = "not_executed",
        arguments: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Direct helper to record an arbitrary security event or execution outcome with unique event_id."""
        if not self.config.is_configured or self._closed:
            return False

        clean_args = redact_sensitive_data(arguments or {})
        event = TelemetryEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=agent or "unknown",
            tool=tool or "unknown",
            decision=decision or "BLOCK",
            allowed=allowed,
            reasons=list(reasons or []),
            rules_triggered=[r.split(":")[0].strip() for r in (reasons or []) if ":" in r],
            risk_score=float(risk_score),
            severity=severity or "LOW",
            execution_status=execution_status,
            arguments=clean_args,
            error=str(error) if error else None,
            correlation_id=correlation_id,
            trace_id=trace_id,
            metadata=metadata or {},
            event_type=event_type,
        )
        return self.record(event)

    def _drain_spool(self, max_batches: int = 5) -> int:
        """Replays spooled events while endpoint is healthy."""
        if not self.spool or self.spool.count() == 0:
            return 0
        replayed = 0
        for _ in range(max_batches):
            ids, payloads = self.spool.fetch_batch(limit=self.config.batch_size)
            if not payloads:
                break
            events = [TelemetryEvent.from_dict(p) for p in payloads]
            if self._transmit_batch(events):
                self.spool.delete_batch(ids)
                replayed += len(events)
                with self._lock:
                    self._stats["replayed"] += len(events)
                    self._stats["sent"] += len(events)
            else:
                break
        return replayed

    def replay_spool(self, max_batches: int = 20) -> int:
        """Public method to manually or synchronously trigger replay of all spooled events."""
        return self._drain_spool(max_batches=max_batches)

    def _worker_loop(self) -> None:
        """Internal background loop collecting batches, transmitting them, and managing spool."""
        while not self._stop_event.is_set():
            batch: List[TelemetryEvent] = []
            try:
                # Wait for at least one event with responsive polling slice
                item = self._queue.get(timeout=min(0.1, max(0.01, self.config.flush_interval_seconds)))
                batch.append(item)

                # Drain remaining items up to batch size without blocking
                while len(batch) < self.config.batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break

            except queue.Empty:
                # Idle queue: attempt replay of any spooled events
                if self.spool and self.spool.count() > 0:
                    self._drain_spool(max_batches=2)
                continue

            if batch:
                success = self._transmit_batch(batch)
                if success:
                    with self._lock:
                        self._stats["sent"] += len(batch)
                    self._drain_spool(max_batches=2)
                else:
                    with self._lock:
                        self._stats["retry_exhausted"] += len(batch)
                    if self.spool:
                        spooled = self.spool.spool_events(batch)
                        with self._lock:
                            self._stats["spooled"] += spooled
                            self._stats["dropped"] += (len(batch) - spooled)
                    else:
                        with self._lock:
                            self._stats["dropped"] += len(batch)

                for _ in batch:
                    self._queue.task_done()

    def _transmit_batch(self, batch: List[TelemetryEvent]) -> bool:
        """
        Sends a batch of TelemetryEvents to the hosted ingestion endpoint.
        Handles retries, network timeouts, authentication errors, and payload framing.
        """
        if not batch or not self.config.api_url or not self.config.api_key:
            return False

        base_url = self.config.api_url.rstrip("/")
        endpoints = [
            f"{base_url}/api/v1/telemetry/events",
            f"{base_url}/api/telemetry/events",
        ]

        payload = {
            "events": [e.to_dict() for e in batch],
        }
        if self.config.tenant_id:
            payload["tenant_id"] = self.config.tenant_id

        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.config.api_key,
            "Authorization": f"Bearer {self.config.api_key}",
            "User-Agent": "AgentShield-SDK-Telemetry/1.0",
        }
        if self.config.tenant_id:
            headers["X-Tenant-ID"] = self.config.tenant_id

        for url in endpoints:
            success = self._send_http_with_retries(url, data, headers)
            if success:
                return True
        return False

    def _send_http_with_retries(self, url: str, data: bytes, headers: Dict[str, str]) -> bool:
        """Executes HTTP request with exponential backoff for transient failures."""
        for attempt in range(self.config.max_retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                    if 200 <= response.status < 300:
                        with self._lock:
                            self._last_successful_transmission = datetime.now(timezone.utc).isoformat()
                            self._last_transmission_error = None
                        return True
                    logger.warning("Telemetry ingestion returned non-200 status: %d", response.status)
                    with self._lock:
                        self._last_transmission_error = f"HTTP {response.status}"
                    return False

            except urllib.error.HTTPError as e:
                # 401 Unauthorized or 403 Forbidden: bad key or cross-tenant, do not retry
                if e.code in (401, 403):
                    logger.error("AgentShield telemetry ingestion authorization failed (HTTP %d). Check API key.", e.code)
                    with self._lock:
                        self._last_transmission_error = f"HTTP {e.code}: Authorization failed"
                    return False
                # 404: Endpoint not found, break so caller can try fallback route
                if e.code == 404:
                    with self._lock:
                        self._last_transmission_error = "HTTP 404: Endpoint not found"
                    return False

                # Retryable server errors (500, 502, 503, 504)
                if attempt < self.config.max_retries and e.code in (500, 502, 503, 504):
                    backoff = self.config.retry_backoff_base * (2 ** attempt)
                    time.sleep(backoff)
                    continue

                logger.warning("Telemetry ingestion failed with HTTP %d: %s", e.code, e.reason)
                with self._lock:
                    self._last_transmission_error = f"HTTP {e.code}: {e.reason}"
                return False

            except (urllib.error.URLError, TimeoutError, OSError) as e:
                # Transient network error, retry if attempts remain
                if attempt < self.config.max_retries:
                    backoff = self.config.retry_backoff_base * (2 ** attempt)
                    time.sleep(backoff)
                    continue

                # Strip API key from error string if it somehow got included in URL
                err_str = str(e)
                if self.config.api_key and self.config.api_key in err_str:
                    err_str = err_str.replace(self.config.api_key, "[REDACTED_KEY]")
                logger.warning("Telemetry network transmission error: %s", err_str)
                with self._lock:
                    self._last_transmission_error = err_str
                return False

        return False

    def flush(self, timeout: float = 5.0) -> bool:
        """
        Drains all queued telemetry events and replays spooled events.
        Returns True ONLY if all queued and spooled events were completely delivered.
        Returns False if any events remain pending when timeout expires.
        """
        if not self.config.is_configured:
            return True

        start = time.perf_counter()
        while not self._queue.empty():
            # If worker is not running, drain directly
            if self._worker_thread is None or not self._worker_thread.is_alive():
                batch = []
                while not self._queue.empty() and len(batch) < self.config.batch_size:
                    batch.append(self._queue.get())
                if batch:
                    success = self._transmit_batch(batch)
                    if success:
                        with self._lock:
                            self._stats["sent"] += len(batch)
                    else:
                        if self.spool:
                            spooled = self.spool.spool_events(batch)
                            with self._lock:
                                self._stats["spooled"] += spooled
                        else:
                            with self._lock:
                                self._stats["dropped"] += len(batch)
            else:
                time.sleep(0.05)

            if (time.perf_counter() - start) > timeout:
                return False

        # Drain persistent spool if network is available
        if self.spool and self.spool.count() > 0:
            self._drain_spool(max_batches=20)

        spool_left = self.spool.count() if self.spool else 0
        return self._queue.empty() and spool_left == 0

    def close(self, timeout: float = 5.0) -> bool:
        """
        Gracefully flushes pending events, replays spooled records, and terminates the worker.
        Returns True if ALL events were completely delivered.
        Returns False if any events remain pending/undelivered.
        """
        with self._lock:
            if self._closed:
                return True
            self._closed = True

        try:
            atexit.unregister(self.close)
        except Exception:
            pass

        all_delivered = self.flush(timeout=timeout)
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
            self._worker_thread = None
        return all_delivered

