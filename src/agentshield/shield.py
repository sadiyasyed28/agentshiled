import functools
import hashlib
import hmac
import inspect
import os
import secrets
import threading
import time
from typing import Any, Optional, Dict, List, Set, Tuple, Callable, Union
import uuid
from agentshield.models import (
    Action,
    Decision,
    DecisionValue,
    RiskLevel,
    FrozenDict,
    normalize_and_freeze,
    unfreeze_value,
)
from agentshield.tools.registry import ToolRegistry, RegisteredTool
from agentshield.policy.engine import PolicyEngine
from agentshield.policy.rules import PolicyConfiguration, AgentConfig, ToolRule
from agentshield.review import ReviewStore, SQLiteReviewStore, ReviewExecutionState, FencingError
from agentshield.secrets import SecretProvider, resolve_secret_references, is_secret_reference
from agentshield.events import (
    EventStore,
    SQLiteEventStore,
    SecurityEventManager,
    SecurityEvent,
    EventType,
    EventSeverity,
)

from enum import Enum

class ExecutionStatus(Enum):
    EXECUTED = "executed"
    NOT_EXECUTED = "not_executed"
    ERROR = "error"

class ReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class ExecutionResult:
    def __init__(
        self,
        decision: Decision,
        execution_status: ExecutionStatus,
        tool_result: Any = None,
        error: Optional[str] = None
    ):
        self.decision = decision
        self.execution_status = execution_status
        self.tool_result = tool_result
        self.error = error


class ToolBlockedError(PermissionError):
    """Raised when an invocation of a protected tool is blocked by policy or risk evaluation."""
    def __init__(self, message: str, decision: Decision, tool_name: str, agent: str):
        super().__init__(message)
        self.decision = decision
        self.tool_name = tool_name
        self.agent = agent
        self.reasons = list(decision.reasons)
        self.risk_score = decision.risk_score


class ToolReviewRequiredError(PermissionError):
    """Raised when an invocation of a protected tool requires human approval before execution."""
    def __init__(self, message: str, decision: Decision, tool_name: str, agent: str, review_id: Optional[str] = None):
        super().__init__(message)
        self.decision = decision
        self.tool_name = tool_name
        self.agent = agent
        self.reasons = list(decision.reasons)
        self.risk_score = decision.risk_score
        self.review_id = review_id or getattr(decision, "review_id", None)


class _ReviewQueueProxy:
    """Proxy mapping that exposes pending reviews from the persistent review store as a dict-like interface."""
    def __init__(self, review_store: ReviewStore, shield: "Shield"):
        self._store = review_store
        self._shield = shield

    def __getitem__(self, key: str) -> Dict[str, Any]:
        self._shield._cleanup_expired_reviews()
        item = self._store.get_review(key)
        if item is None or item.get("status") != ReviewStatus.PENDING.value:
            raise KeyError(key)
        return item

    def __contains__(self, key: str) -> bool:
        self._shield._cleanup_expired_reviews()
        item = self._store.get_review(key)
        return item is not None and item.get("status") == ReviewStatus.PENDING.value

    def __len__(self) -> int:
        self._shield._cleanup_expired_reviews()
        return len(self._store.get_pending_reviews())

    def __iter__(self):
        self._shield._cleanup_expired_reviews()
        for item in self._store.get_pending_reviews():
            yield item["review_id"]

    def keys(self) -> List[str]:
        self._shield._cleanup_expired_reviews()
        return [item["review_id"] for item in self._store.get_pending_reviews()]

    def values(self) -> List[Dict[str, Any]]:
        self._shield._cleanup_expired_reviews()
        return self._store.get_pending_reviews()

    def items(self) -> List[Tuple[str, Dict[str, Any]]]:
        self._shield._cleanup_expired_reviews()
        return [(item["review_id"], item) for item in self._store.get_pending_reviews()]

    def get(self, key: str, default: Any = None) -> Any:
        self._shield._cleanup_expired_reviews()
        item = self._store.get_review(key)
        if item is None or item.get("status") != ReviewStatus.PENDING.value:
            return default
        return item

    def pop(self, key: str, default: Any = None) -> Any:
        item = self._store.get_review(key)
        if item is None or item.get("status") != ReviewStatus.PENDING.value:
            return default
        return item

class _ReviewHistoryProxy:
    def __init__(self, review_store: ReviewStore):
        self._store = review_store

    def __getitem__(self, key: str) -> Dict[str, Any]:
        item = self._store.get_review(key)
        if item is None:
            raise KeyError(key)
        return item

    def __contains__(self, key: str) -> bool:
        return self._store.get_review(key) is not None

    def get(self, key: str, default: Any = None) -> Any:
        item = self._store.get_review(key)
        return item if item is not None else default

    def __setitem__(self, key: str, value: Any) -> None:
        pass

class _ExecutedReviewsProxy:
    def __init__(self, review_store: ReviewStore):
        self._store = review_store

    def __contains__(self, key: str) -> bool:
        item = self._store.get_review(key)
        if item and item.get("execution_state") in ("executing", "succeeded", "failed", "outcome_unknown", "approved", "executed", "error"):
            return True
        return False

    def add(self, key: str) -> None:
        pass

from agentshield.risk.engine import RiskEngine
from agentshield.audit.store import AuditStore, SQLiteAuditStore

def _hash_credential(key: str, salt: bytes) -> str:
    """Hashes an API key with PBKDF2-HMAC-SHA256 (100,000 iterations) and returns a 64-char hex digest."""
    return hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, 100_000).hex()

def _hash_key(key: str) -> str:
    """Computes a SHA-256 hex digest of a key (kept for backward compatibility)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

class Shield:
    def __init__(
        self,
        risk_engine: Optional[RiskEngine] = None,
        audit_store: Optional[AuditStore] = None,
        agent_keys: Optional[Dict[str, str]] = None,
        review_ttl_seconds: float = 300.0,
        review_store: Optional[ReviewStore] = None,
        secret_provider: Optional[SecretProvider] = None,
        enforce_secret_references: bool = False,
        lease_duration: float = 60.0,
        heartbeat_enabled: bool = True,
        event_store: Optional[EventStore] = None,
        event_manager: Optional[SecurityEventManager] = None,
        analyst: Optional[Any] = None,
        reliability_config: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
        loop_detector: Optional[Any] = None,
        budget_tracker: Optional[Any] = None,
        max_tool_execution_seconds: Optional[float] = None,
        logger: Optional[Any] = None,
        metrics_collector: Optional[Any] = None,
        policy: Optional[Any] = None,
        policy_config: Optional[Any] = None,
    ):
        self.registry = ToolRegistry()
        self.analyst = analyst
        self.secret_provider = secret_provider
        self.enforce_secret_references = enforce_secret_references
        self.lease_duration = lease_duration
        self.heartbeat_enabled = heartbeat_enabled

        from agentshield.reliability.config import ReliabilityConfig
        from agentshield.reliability.limits import SessionBudgetTracker
        from agentshield.reliability.loop_detector import LoopDetector

        self.reliability_config = reliability_config or ReliabilityConfig.from_env()
        if max_tool_execution_seconds is not None:
            self.reliability_config.max_tool_execution_seconds = max_tool_execution_seconds
        self.rate_limiter = rate_limiter
        self.loop_detector = loop_detector or LoopDetector(
            consecutive_limit=self.reliability_config.loop_consecutive_limit,
            cycle_limit=self.reliability_config.loop_cycle_limit,
        )
        self.budget_tracker = budget_tracker or SessionBudgetTracker()
        effective_policy = policy if policy is not None else policy_config
        if effective_policy is not None:
            if isinstance(effective_policy, PolicyConfiguration):
                config = effective_policy
            elif isinstance(effective_policy, dict):
                config = PolicyConfiguration.from_dict(effective_policy)
            else:
                raise TypeError(
                    f"policy must be a PolicyConfiguration or dict, got {type(effective_policy).__name__}"
                )
        else:
            config = PolicyConfiguration(
                agents={
                    "shopping_agent": AgentConfig(
                        name="shopping_agent",
                        allowed_tools=["search_product", "get_product", "create_order"],
                        denied_tools=["refund_order"]
                    )
                },
                tools={
                    "create_order": ToolRule(tool="create_order", max_quantity=10),
                    "refund_order": ToolRule(tool="refund_order", max_amount=10000, required_permissions=["refund"])
                }
            )
        self.policy_engine = PolicyEngine(config)
        self.risk_engine = risk_engine or RiskEngine()
        self.audit_store = audit_store
        self.review_ttl_seconds = review_ttl_seconds

        # Persistent Review Store initialization (isolated from audit store)
        if review_store is not None:
            self.review_store = review_store
        elif audit_store is not None and getattr(audit_store, "db_path", None) == ":memory:":
            self.review_store = SQLiteReviewStore(db_path=":memory:")
        elif audit_store is not None and getattr(audit_store, "db_path", None):
            audit_dir = os.path.dirname(audit_store.db_path)
            audit_base = os.path.basename(audit_store.db_path)
            rev_name = "agentshield_reviews.db" if audit_base == "agentshield_audit.db" else f"review_{audit_base}"
            rev_path = os.path.join(audit_dir, rev_name) if audit_dir else rev_name
            self.review_store = SQLiteReviewStore(db_path=rev_path)
        elif os.environ.get("AGENTSHIELD_REVIEW_DB"):
            self.review_store = SQLiteReviewStore(db_path=os.environ["AGENTSHIELD_REVIEW_DB"])
        else:
            self.review_store = SQLiteReviewStore(db_path=":memory:")

        # Backwards-compatible proxy mappings backed by SQLiteReviewStore
        self._review_queue = _ReviewQueueProxy(self.review_store, self)
        self._review_history = _ReviewHistoryProxy(self.review_store)
        self._executed_reviews = _ExecutedReviewsProxy(self.review_store)

        # Security Event and Alert Manager initialization
        if event_manager is not None:
            self.event_manager = event_manager
        elif event_store is not None:
            self.event_manager = SecurityEventManager(store=event_store)
        elif audit_store is not None and getattr(audit_store, "db_path", None) == ":memory:":
            self.event_manager = SecurityEventManager(store=SQLiteEventStore(db_path=":memory:"))
        elif audit_store is not None and getattr(audit_store, "db_path", None):
            audit_dir = os.path.dirname(audit_store.db_path)
            audit_base = os.path.basename(audit_store.db_path)
            evt_name = "agentshield_events.db" if audit_base == "agentshield_audit.db" else f"events_{audit_base}"
            evt_path = os.path.join(audit_dir, evt_name) if audit_dir else evt_name
            self.event_manager = SecurityEventManager(store=SQLiteEventStore(db_path=evt_path))
        elif os.environ.get("AGENTSHIELD_EVENTS_DB"):
            self.event_manager = SecurityEventManager(store=SQLiteEventStore(db_path=os.environ["AGENTSHIELD_EVENTS_DB"]))
        else:
            self.event_manager = SecurityEventManager(store=SQLiteEventStore(db_path=":memory:"))

        # Agent identity: securely store salted PBKDF2 hashes of agent authentication keys
        self.agent_keys: Dict[str, str] = {}
        self._agent_salts: Dict[str, bytes] = {}
        self._retired_agent_keys: Dict[str, List[Tuple[bytes, str]]] = {}
        if agent_keys:
            for ag, k in agent_keys.items():
                self.register_agent_key(ag, k)

        # Paused agents set (incident response kill-switch)
        self._paused_agents: Set[str] = set()

        # Observability & Monitoring
        from agentshield.observability import get_operational_logger, get_metrics_collector
        self.logger = logger or get_operational_logger()
        self.metrics_collector = metrics_collector or get_metrics_collector()
        self.metrics_collector.register_gauge("pending_reviews", lambda: len(self.get_review_queue()))
        self.metrics_collector.register_gauge("paused_agents", lambda: len(self._paused_agents))
        if self.event_manager and hasattr(self.event_manager, "store"):
            self.metrics_collector.register_gauge(
                "active_incidents",
                lambda: len(self.event_manager.store.query_incidents(status="open", limit=100)),
            )

    def register_agent_key(self, agent: str, key: str) -> None:
        """Registers a fresh salted PBKDF2-HMAC-SHA256 credential for an agent."""
        salt = secrets.token_bytes(16)
        self._agent_salts[agent] = salt
        self.agent_keys[agent] = _hash_credential(key, salt)

    def rotate_agent_key(self, agent: str, new_key: str, retire_old: bool = True) -> None:
        """Rotates an agent's API key with a fresh random salt.
        If retire_old is False, previously configured credentials remain accepted.
        """
        new_salt = secrets.token_bytes(16)
        new_hash = _hash_credential(new_key, new_salt)
        if not retire_old and agent in self.agent_keys:
            old_salt = self._agent_salts.get(agent)
            old_hash = self.agent_keys.get(agent)
            if old_salt and old_hash:
                if agent not in self._retired_agent_keys:
                    self._retired_agent_keys[agent] = []
                self._retired_agent_keys[agent].append((old_salt, old_hash))
        elif retire_old and agent in self._retired_agent_keys:
            self._retired_agent_keys.pop(agent, None)

        self._agent_salts[agent] = new_salt
        self.agent_keys[agent] = new_hash

    def load_policy(
        self,
        policy: Any
    ) -> PolicyConfiguration:
        """Loads a declarative policy configuration into the shield's policy engine.

        Args:
            policy: A PolicyConfiguration instance, a dictionary, or a YAML string/Path.

        Returns:
            The loaded PolicyConfiguration instance.
        """
        from pathlib import Path
        if isinstance(policy, PolicyConfiguration):
            loaded_config = policy
        elif isinstance(policy, dict):
            loaded_config = PolicyConfiguration.from_dict(policy)
        elif isinstance(policy, (str, Path)):
            loaded_config = PolicyConfiguration.from_yaml(policy)
        else:
            raise TypeError(f"Unsupported policy type: {type(policy).__name__}")

        self.policy_engine = PolicyEngine(loaded_config)
        return loaded_config

    def set_policy(self, policy: PolicyConfiguration) -> None:
        """Sets the active PolicyConfiguration on the policy engine."""
        if not isinstance(policy, PolicyConfiguration):
            raise TypeError(f"policy must be a PolicyConfiguration instance, got {type(policy).__name__}")
        self.policy_engine = PolicyEngine(policy)

    def protect_tool(
        self,
        func: Optional[Callable[..., Any]] = None,
        *,
        name: Optional[str] = None,
        agent: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        read_only: bool = False,
        idempotent: bool = False,
        guarantees_deduplication: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raise_on_blocked: bool = True,
    ) -> Callable[..., Any]:
        """Decorator that wraps a tool callable with deterministic AgentShield policy enforcement.

        Invariants:
        - ALLOW: Invokes the original callable exactly once and records audit telemetry.
        - BLOCK: Never invokes the original callable; audits failure and raises ToolBlockedError
                 (or returns an ExecutionResult if raise_on_blocked=False).
        - REVIEW: Never invokes the original callable before human approval; enqueues review and
                  raises ToolReviewRequiredError (or returns an ExecutionResult).
        - Preserves the wrapped function's signature, docstring, and metadata via functools.wraps.
        - Supports both synchronous and asynchronous functions.

        Args:
            func: The function to decorate (when used as bare @shield.protect_tool).
            name: Explicit tool name (defaults to func.__name__).
            agent: Default agent identity for invocations of this tool.
            permissions: Required or granted permissions for this tool.
            read_only: Whether the tool performs read-only operations.
            idempotent: Whether the tool is idempotent.
            guarantees_deduplication: Whether the tool guarantees downstream deduplication on retries.
            metadata: Additional metadata dictionary to attach to the registered tool.
            raise_on_blocked: If True (default), raises ToolBlockedError/ToolReviewRequiredError on rejection.
                              If False, returns ExecutionResult.

        Returns:
            Wrapped callable.
        """
        def _decorator(target_func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or target_func.__name__

            # Register with shield's tool registry so policy engine and reviews recognize it
            self.registry.register(
                name=tool_name,
                callable_func=target_func,
                metadata=metadata,
                required_permissions=permissions,
                idempotent=idempotent,
                guarantees_deduplication=guarantees_deduplication,
                read_only=read_only,
            )

            sig = inspect.signature(target_func)
            param_names = set(sig.parameters.keys())
            is_async = inspect.iscoroutinefunction(target_func)

            def _prepare_call(call_args: tuple, call_kwargs: dict):
                clean_kwargs = dict(call_kwargs)

                # Extract security context arguments if passed by caller
                caller_agent = clean_kwargs.pop("_agent", None)
                if caller_agent is None and "agent_id" in clean_kwargs and "agent_id" not in param_names:
                    caller_agent = clean_kwargs.pop("agent_id")
                effective_agent = caller_agent if caller_agent is not None else (agent or "")

                caller_perms = clean_kwargs.pop("_permissions", None)
                if caller_perms is None and "permissions" in clean_kwargs and "permissions" not in param_names:
                    caller_perms = clean_kwargs.pop("permissions")
                effective_perms = caller_perms if caller_perms is not None else (permissions or [])

                caller_key = clean_kwargs.pop("_agent_key", None)
                caller_corr = clean_kwargs.pop("_correlation_id", None)
                caller_trace = clean_kwargs.pop("_trace_id", None)

                # Bind arguments for policy evaluation
                try:
                    bound = sig.bind_partial(*call_args, **clean_kwargs)
                    bound.apply_defaults()
                    eval_args = dict(bound.arguments)
                except TypeError:
                    eval_args = dict(clean_kwargs)
                    for idx, a in enumerate(call_args):
                        eval_args[f"arg_{idx}"] = a

                # Authorize
                decision = self.authorize(
                    agent=effective_agent,
                    tool=tool_name,
                    arguments=eval_args,
                    permissions=effective_perms,
                    agent_key=caller_key,
                    correlation_id=caller_corr,
                    trace_id=caller_trace,
                )

                return effective_agent, clean_kwargs, decision

            def _handle_non_allow(decision: Decision, effective_agent: str) -> Optional[ExecutionResult]:
                policy_hash = self.policy_engine.version_hash
                if self.audit_store:
                    try:
                        self.audit_store.log_decision(
                            decision,
                            decision.arguments,
                            execution_status="not_executed",
                            policy_version_hash=policy_hash,
                        )
                    except Exception:
                        pass
                self._publish_security_event(
                    agent_id=decision.agent,
                    tool=decision.tool,
                    event_type=EventType.EXECUTION_OUTCOME.value,
                    severity=EventSeverity.LOW.value if decision.decision == DecisionValue.REVIEW else EventSeverity.MEDIUM.value,
                    decision=decision.decision.value,
                    risk_score=decision.risk_score,
                    evidence=decision.reasons,
                    trace_id=decision.trace_id,
                    correlation_id=decision.correlation_id,
                    metadata={"execution_status": "not_executed", "arguments": decision.arguments},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_execution("not_executed", duration_ms=0.0)
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_execution(
                        agent=decision.agent,
                        tool=decision.tool,
                        status="not_executed",
                        correlation_id=decision.correlation_id,
                        trace_id=decision.trace_id,
                        latency_ms=0.0,
                        arguments=decision.arguments,
                    )

                if decision.decision == DecisionValue.REVIEW:
                    rev_id = getattr(decision, "review_id", None)
                    if raise_on_blocked:
                        raise ToolReviewRequiredError(
                            f"Tool '{tool_name}' for agent '{effective_agent}' requires human review"
                            f"{f' (review_id: {rev_id})' if rev_id else ''}",
                            decision=decision,
                            tool_name=tool_name,
                            agent=effective_agent,
                            review_id=rev_id,
                        )
                    return ExecutionResult(
                        decision=decision,
                        execution_status=ExecutionStatus.NOT_EXECUTED,
                        tool_result=None,
                    )

                # BLOCK
                if raise_on_blocked:
                    reasons_str = "; ".join(decision.reasons) if decision.reasons else "Blocked by policy"
                    raise ToolBlockedError(
                        f"Tool '{tool_name}' blocked for agent '{effective_agent}': {reasons_str}",
                        decision=decision,
                        tool_name=tool_name,
                        agent=effective_agent,
                    )
                return ExecutionResult(
                    decision=decision,
                    execution_status=ExecutionStatus.NOT_EXECUTED,
                    tool_result=None,
                )

            def _audit_and_log_success(decision: Decision, effective_agent: str, duration_ms: float) -> None:
                policy_hash = self.policy_engine.version_hash
                if self.audit_store:
                    self.audit_store.log_decision(
                        decision,
                        decision.arguments,
                        execution_status="executed",
                        policy_version_hash=policy_hash,
                    )
                self._publish_security_event(
                    agent_id=effective_agent,
                    tool=tool_name,
                    event_type=EventType.EXECUTION_OUTCOME.value,
                    severity=EventSeverity.LOW.value,
                    decision="ALLOW",
                    risk_score=decision.risk_score,
                    evidence=["Tool executed successfully via decorator"],
                    trace_id=decision.trace_id,
                    correlation_id=decision.correlation_id,
                    metadata={"execution_status": "executed", "arguments": decision.arguments},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_execution("executed", duration_ms=duration_ms)
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_execution(
                        agent=effective_agent,
                        tool=tool_name,
                        status="executed",
                        correlation_id=decision.correlation_id,
                        trace_id=decision.trace_id,
                        latency_ms=duration_ms,
                        arguments=decision.arguments,
                    )

            def _audit_and_log_error(decision: Decision, effective_agent: str, error_msg: str, duration_ms: float) -> None:
                policy_hash = self.policy_engine.version_hash
                if self.audit_store:
                    self.audit_store.log_decision(
                        decision,
                        decision.arguments,
                        execution_status="error",
                        error=error_msg,
                        policy_version_hash=policy_hash,
                    )
                self._publish_security_event(
                    agent_id=effective_agent,
                    tool=tool_name,
                    event_type=EventType.EXECUTION_OUTCOME.value,
                    severity=EventSeverity.MEDIUM.value,
                    decision="ALLOW",
                    risk_score=decision.risk_score,
                    evidence=[f"Tool error: {error_msg}"],
                    trace_id=decision.trace_id,
                    correlation_id=decision.correlation_id,
                    metadata={"execution_status": "error", "error": error_msg, "arguments": decision.arguments},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_execution("error", duration_ms=duration_ms)
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_execution(
                        agent=effective_agent,
                        tool=tool_name,
                        status="error",
                        correlation_id=decision.correlation_id,
                        trace_id=decision.trace_id,
                        latency_ms=duration_ms,
                        error=error_msg,
                        arguments=decision.arguments,
                    )

            if is_async:
                @functools.wraps(target_func)
                async def async_wrapper(*call_args: Any, **call_kwargs: Any) -> Any:
                    effective_agent, clean_kwargs, decision = _prepare_call(call_args, call_kwargs)
                    if decision.decision != DecisionValue.ALLOW or not decision.allowed:
                        return _handle_non_allow(decision, effective_agent)

                    frozen_args = decision.arguments
                    exec_args = unfreeze_value(frozen_args) if frozen_args is not None else dict(clean_kwargs)
                    try:
                        bound_exec = sig.bind_partial(**exec_args)
                        bound_exec.apply_defaults()
                        exec_call_args = bound_exec.args
                        exec_call_kwargs = bound_exec.kwargs
                    except (TypeError, ValueError):
                        exec_call_args = call_args
                        exec_call_kwargs = clean_kwargs

                    start_exec = time.perf_counter()
                    try:
                        res = await target_func(*exec_call_args, **exec_call_kwargs)
                        duration_ms = (time.perf_counter() - start_exec) * 1000.0
                        _audit_and_log_success(decision, effective_agent, duration_ms)
                        if not raise_on_blocked:
                            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
                        return res
                    except Exception as exc:
                        duration_ms = (time.perf_counter() - start_exec) * 1000.0
                        _audit_and_log_error(decision, effective_agent, str(exc), duration_ms)
                        raise

                async_wrapper.__shield_tool__ = tool_name
                async_wrapper.__shield__ = self
                async_wrapper.__signature__ = sig
                try:
                    del async_wrapper.__wrapped__
                except (AttributeError, KeyError):
                    pass
                return async_wrapper

            else:
                @functools.wraps(target_func)
                def sync_wrapper(*call_args: Any, **call_kwargs: Any) -> Any:
                    effective_agent, clean_kwargs, decision = _prepare_call(call_args, call_kwargs)
                    if decision.decision != DecisionValue.ALLOW or not decision.allowed:
                        return _handle_non_allow(decision, effective_agent)

                    frozen_args = decision.arguments
                    exec_args = unfreeze_value(frozen_args) if frozen_args is not None else dict(clean_kwargs)
                    try:
                        bound_exec = sig.bind_partial(**exec_args)
                        bound_exec.apply_defaults()
                        exec_call_args = bound_exec.args
                        exec_call_kwargs = bound_exec.kwargs
                    except (TypeError, ValueError):
                        exec_call_args = call_args
                        exec_call_kwargs = clean_kwargs

                    start_exec = time.perf_counter()
                    try:
                        res = target_func(*exec_call_args, **exec_call_kwargs)
                        duration_ms = (time.perf_counter() - start_exec) * 1000.0
                        _audit_and_log_success(decision, effective_agent, duration_ms)
                        if not raise_on_blocked:
                            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
                        return res
                    except Exception as exc:
                        duration_ms = (time.perf_counter() - start_exec) * 1000.0
                        _audit_and_log_error(decision, effective_agent, str(exc), duration_ms)
                        raise

                sync_wrapper.__shield_tool__ = tool_name
                sync_wrapper.__shield__ = self
                sync_wrapper.__signature__ = sig
                try:
                    del sync_wrapper.__wrapped__
                except (AttributeError, KeyError):
                    pass
                return sync_wrapper

        if func is not None:
            return _decorator(func)
        return _decorator

    tool = protect_tool

    def protect_langchain_tool(
        self,
        tool: Any,
        agent: Optional[str] = None,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        correlation_id: Optional[str] = None,
        raise_on_blocked: bool = True,
        read_only: bool = False,
        idempotent: bool = False,
        guarantees_deduplication: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Wraps a LangChain BaseTool with AgentShield runtime security policy enforcement.

        Requires 'langchain-core' (install via `pip install agentshield[langchain]`).
        """
        from agentshield.integrations.langchain import protect_langchain_tool
        return protect_langchain_tool(
            tool=tool,
            shield=self,
            agent=agent,
            name=name,
            description=description,
            permissions=permissions,
            correlation_id=correlation_id,
            raise_on_blocked=raise_on_blocked,
            read_only=read_only,
            idempotent=idempotent,
            guarantees_deduplication=guarantees_deduplication,
            metadata=metadata,
        )

    def protect_crewai_tool(
        self,
        tool: Any,
        agent: Optional[str] = None,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        correlation_id: Optional[str] = None,
        raise_on_blocked: bool = True,
        read_only: bool = False,
        idempotent: bool = False,
        guarantees_deduplication: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Wraps a CrewAI BaseTool with AgentShield runtime security policy enforcement.

        Requires 'crewai' (install via `pip install agentshield[crewai]`).
        """
        from agentshield.integrations.crewai import protect_crewai_tool
        return protect_crewai_tool(
            tool=tool,
            shield=self,
            agent=agent,
            name=name,
            description=description,
            permissions=permissions,
            correlation_id=correlation_id,
            raise_on_blocked=raise_on_blocked,
            read_only=read_only,
            idempotent=idempotent,
            guarantees_deduplication=guarantees_deduplication,
            metadata=metadata,
        )

    def _audit_action(
        self,
        action_name: str,
        agent: str,
        actor: str,
        decision_val: DecisionValue,
        reasons: List[str],
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.audit_store:
            return
        trace_id = details.get("trace_id") if details else None
        correlation_id = details.get("correlation_id") if details else None
        dec = Decision(
            allowed=(decision_val == DecisionValue.ALLOW),
            decision=decision_val,
            reasons=reasons,
            risk_score=0.0,
            severity=RiskLevel.LOW,
            agent=agent,
            tool=f"incident:{action_name}",
            trace_id=trace_id,
            correlation_id=correlation_id,
        )
        args = {"actor": actor, "incident_action": action_name}
        if details:
            args.update(details)
        self.audit_store.log_decision(
            decision=dec,
            arguments=args,
            execution_status="executed" if decision_val == DecisionValue.ALLOW else "not_executed",
            policy_version_hash=self.policy_engine.version_hash
        )
        self._publish_security_event(
            agent_id=agent,
            tool=f"incident:{action_name}",
            event_type=EventType.REVIEW_ACTION.value if action_name in ("approve", "reject", "enqueue", "expired", "unpause") else EventType.SECURITY_FAILURE.value,
            severity=EventSeverity.CRITICAL.value if action_name == "pause" else EventSeverity.LOW.value,
            decision=decision_val.value,
            evidence=reasons,
            trace_id=trace_id,
            correlation_id=correlation_id,
            metadata=args,
        )

    def _publish_security_event(
        self,
        agent_id: str,
        tool: str,
        event_type: str,
        severity: str,
        decision: Optional[str] = None,
        risk_score: float = 0.0,
        evidence: Optional[List[str]] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[SecurityEvent]:
        if not getattr(self, "event_manager", None):
            return None
        try:
            return self.event_manager.publish_event(
                agent_id=agent_id,
                tool=tool,
                event_type=event_type,
                severity=severity,
                decision=decision,
                risk_score=risk_score,
                evidence=evidence or [],
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata=metadata or {},
            )
        except Exception:
            return None

    def pause_agent(self, agent: str, actor: str = "system") -> None:
        """Pauses an agent immediately; all actions fail closed to BLOCK."""
        self._paused_agents.add(agent)
        self._audit_action(
            action_name="pause",
            agent=agent,
            actor=actor,
            decision_val=DecisionValue.BLOCK,
            reasons=[f"Agent '{agent}' paused by {actor}"]
        )

    def unpause_agent(self, agent: str, actor: str = "system") -> None:
        """Unpauses an agent."""
        self._paused_agents.discard(agent)
        self._audit_action(
            action_name="unpause",
            agent=agent,
            actor=actor,
            decision_val=DecisionValue.ALLOW,
            reasons=[f"Agent '{agent}' unpaused by {actor}"]
        )

    def is_agent_paused(self, agent: str) -> bool:
        """Returns True if the agent is currently paused."""
        return agent in self._paused_agents

    def _cleanup_expired_reviews(self) -> None:
        now = time.time()
        expired_items = self.review_store.expire_pending(now)
        for item in expired_items:
            orig_dec = item.get("decision")
            self._audit_action(
                action_name="expired",
                agent=item["agent"],
                actor="system",
                decision_val=DecisionValue.BLOCK,
                reasons=["Review expired and failed closed"],
                details={
                    "review_id": item["review_id"],
                    "status": ReviewStatus.EXPIRED.value,
                    "trace_id": getattr(orig_dec, "trace_id", None) if orig_dec else None,
                    "correlation_id": getattr(orig_dec, "correlation_id", None) if orig_dec else None,
                }
            )

    def get_review_status(self, review_id: str) -> Optional[str]:
        """Returns the current status of a review request ('pending', 'approved', 'rejected', 'expired')."""
        self._cleanup_expired_reviews()
        return self.review_store.get_status(review_id)

    def get_review_execution_state(self, review_id: str) -> Optional[str]:
        """Returns the explicit execution state ('not_started', 'executing', 'succeeded', 'failed', 'outcome_unknown')."""
        return self.review_store.get_execution_state(review_id)

    def get_review_queue(self) -> List[Dict[str, Any]]:
        """Returns the pending unexpired review actions."""
        self._cleanup_expired_reviews()
        return self.review_store.get_pending_reviews()

    def approve_review(
        self, review_id: str, approver: str = "human_reviewer", allow_idempotent_retry: bool = False
    ) -> Optional[ExecutionResult]:
        """Approves and executes an action from the review queue.
        Enforces at-most-once initiation for non-idempotent actions and deduplicated idempotent execution."""
        self._cleanup_expired_reviews()

        item_check = self.review_store.get_review(review_id)
        if not item_check:
            return None

        # Verify idempotency contract: do not treat declared idempotent=True alone as proof of downstream deduplication.
        idempotency_key = item_check.get("idempotency_key")
        has_idempotency_key = bool(idempotency_key)
        tool_reg = self.registry.get_tool(item_check["tool"])
        can_idempotent_retry = False
        if tool_reg:
            can_idempotent_retry = tool_reg.can_safely_retry(has_idempotency_key=has_idempotency_key)
        elif has_idempotency_key and allow_idempotent_retry:
            can_idempotent_retry = True

        worker_id = f"proc_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        lease_sec = self.lease_duration
        # Atomically claim and mark executing with worker ownership and lease
        item = self.review_store.claim_and_approve(
            review_id,
            approver=approver,
            now=time.time(),
            worker_id=worker_id,
            lease_duration=lease_sec,
            allow_idempotent_retry=can_idempotent_retry,
        )
        if not item:
            return None

        # Security invariant: verify agent is not paused
        if self.is_agent_paused(item["agent"]):
            err_msg = f"Agent '{item['agent']}' is currently paused; execution blocked by containment policy"
            self.review_store.mark_executed(
                review_id=review_id,
                execution_state=ReviewExecutionState.FAILED.value,
                error=err_msg,
                worker_id=worker_id,
            )
            self._audit_action(
                action_name="reject",
                agent=item["agent"],
                actor="system:containment",
                decision_val=DecisionValue.BLOCK,
                reasons=[err_msg],
                details={
                    "review_id": review_id,
                    "tool": item["tool"],
                    "status": "blocked_paused_agent",
                }
            )
            return ExecutionResult(
                decision=Decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=[err_msg],
                    risk_score=95.0,
                    severity=RiskLevel.HIGH,
                    agent=item["agent"],
                    tool=item["tool"],
                    arguments=item["arguments"],
                ),
                execution_status=ExecutionStatus.NOT_EXECUTED,
                tool_result=None,
                error=err_msg,
            )

        # Security invariant: re-validate deterministic policy at execution time
        action = Action(agent=item["agent"], tool=item["tool"], arguments=item["arguments"] or {})
        policy_results = self.policy_engine.evaluate(action, permissions=item.get("permissions") or [])
        failed_rules = [pr for pr in policy_results if not pr.passed]
        if failed_rules:
            err_msg = f"Execution blocked by deterministic policy: {'; '.join(pr.reason for pr in failed_rules)}"
            self.review_store.mark_executed(
                review_id=review_id,
                execution_state=ReviewExecutionState.FAILED.value,
                error=err_msg,
                worker_id=worker_id,
            )
            self._audit_action(
                action_name="reject",
                agent=item["agent"],
                actor="system:policy_enforcer",
                decision_val=DecisionValue.BLOCK,
                reasons=[err_msg],
                details={
                    "review_id": review_id,
                    "tool": item["tool"],
                    "status": "blocked_policy_violation",
                }
            )
            return ExecutionResult(
                decision=Decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=[err_msg],
                    risk_score=95.0,
                    severity=RiskLevel.HIGH,
                    agent=item["agent"],
                    tool=item["tool"],
                    arguments=item["arguments"],
                ),
                execution_status=ExecutionStatus.NOT_EXECUTED,
                tool_result=None,
                error=err_msg,
            )

        # Audit approve action
        orig_dec = item.get("decision")
        self._audit_action(
            action_name="approve",
            agent=item["agent"],
            actor=approver,
            decision_val=DecisionValue.ALLOW,
            reasons=[f"Review approved by {approver}"],
            details={
                "review_id": review_id,
                "approver": approver,
                "tool": item["tool"],
                "status": ReviewStatus.APPROVED.value,
                "trace_id": getattr(orig_dec, "trace_id", None) if orig_dec else None,
                "correlation_id": getattr(orig_dec, "correlation_id", None) if orig_dec else None,
            }
        )

        # Override decision to ALLOW upon human approval
        orig_dec = item.get("decision")
        decision = Decision(
            allowed=True,
            decision=DecisionValue.ALLOW,
            reasons=(orig_dec.reasons + [f"Human review approved by {approver}"]) if orig_dec else [f"Human review approved by {approver}"],
            risk_score=orig_dec.risk_score if orig_dec else 0.0,
            severity=orig_dec.severity if orig_dec else RiskLevel.LOW,
            agent=item["agent"],
            tool=item["tool"],
            arguments=item["arguments"],
            trace_id=getattr(orig_dec, "trace_id", None) if orig_dec else None,
            correlation_id=getattr(orig_dec, "correlation_id", None) if orig_dec else None,
        )

        stop_heartbeat = threading.Event()
        fenced_event = threading.Event()
        hb_thread = None

        if self.heartbeat_enabled:
            hb_interval = min(10.0, max(0.05, lease_sec / 3.0))

            def _heartbeat_loop():
                while not stop_heartbeat.wait(timeout=hb_interval):
                    try:
                        ok = self.review_store.heartbeat(review_id, worker_id=worker_id, extension=lease_sec)
                        if not ok:
                            fenced_event.set()
                            break
                    except Exception:
                        pass

            hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True, name=f"hb_{review_id}")
            hb_thread.start()

        try:
            res = self._execute_approved(
                decision,
                item["agent"],
                item["tool"],
                item["arguments"],
                idempotency_key=item.get("idempotency_key"),
            )
            exec_state = (
                ReviewExecutionState.SUCCEEDED.value
                if res.execution_status == ExecutionStatus.EXECUTED
                else ReviewExecutionState.FAILED.value
            )
            persisted = self.review_store.mark_executed(
                review_id=review_id,
                execution_state=exec_state,
                error=res.error,
                worker_id=worker_id,
            )
            if not persisted or fenced_event.is_set():
                raise FencingError(
                    f"Execution worker {worker_id} was fenced out for review {review_id}; lease expired or re-assigned"
                )
            return res
        except Exception as e:
            if not isinstance(e, FencingError):
                try:
                    self.review_store.mark_executed(
                        review_id=review_id,
                        execution_state=ReviewExecutionState.FAILED.value,
                        error=str(e),
                        worker_id=worker_id,
                    )
                except Exception:
                    pass
            raise
        finally:
            stop_heartbeat.set()
            if hb_thread and hb_thread.is_alive():
                hb_thread.join(timeout=1.0)

    def reject_review(self, review_id: str, reason: str = "Rejected by reviewer", reviewer: str = "human_reviewer") -> Optional[Decision]:
        """Rejects a pending action in the review queue."""
        self._cleanup_expired_reviews()
        item = self.review_store.claim_and_reject(review_id, reviewer=reviewer, reason=reason, now=time.time())
        if not item:
            return None

        orig_dec = item.get("decision")
        # Audit reject action
        self._audit_action(
            action_name="reject",
            agent=item["agent"],
            actor=reviewer,
            decision_val=DecisionValue.BLOCK,
            reasons=[f"Review rejected by {reviewer}: {reason}"],
            details={
                "review_id": review_id,
                "reviewer": reviewer,
                "tool": item["tool"],
                "reason": reason,
                "status": ReviewStatus.REJECTED.value,
                "trace_id": getattr(orig_dec, "trace_id", None) if orig_dec else None,
                "correlation_id": getattr(orig_dec, "correlation_id", None) if orig_dec else None,
            }
        )
        return Decision(
            allowed=False,
            decision=DecisionValue.BLOCK,
            reasons=(orig_dec.reasons + [reason]) if orig_dec else [reason],
            risk_score=orig_dec.risk_score if orig_dec else 80.0,
            severity=orig_dec.severity if orig_dec else RiskLevel.HIGH,
            agent=item["agent"],
            tool=item["tool"],
            arguments=item["arguments"],
            trace_id=getattr(orig_dec, "trace_id", None) if orig_dec else None,
            correlation_id=getattr(orig_dec, "correlation_id", None) if orig_dec else None,
        )

    def _finalize_decision(self, dec: Decision, start_time: float) -> Decision:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        if hasattr(self, "metrics_collector") and self.metrics_collector:
            self.metrics_collector.record_decision(dec.decision.value, duration_ms=duration_ms)
        if hasattr(self, "logger") and self.logger:
            self.logger.log_authz(
                agent=dec.agent,
                tool=dec.tool,
                decision=dec.decision.value,
                risk_score=dec.risk_score,
                reasons=dec.reasons,
                correlation_id=dec.correlation_id,
                trace_id=dec.trace_id,
                latency_ms=duration_ms,
            )
        return dec

    def check(self, user_input: str, correlation_id: Optional[str] = None) -> Decision:
        from agentshield.observability.correlation import sanitize_correlation_id, generate_trace_id
        start_time = time.perf_counter()
        risk_result = self.risk_engine.evaluate(user_input=user_input)
        trace_id = generate_trace_id()
        corr_id = sanitize_correlation_id(correlation_id or trace_id)
        if "rm -rf" in user_input or "drop table" in user_input.lower() or risk_result.severity == RiskLevel.CRITICAL:
            reasons = ["Input contains forbidden patterns"]
            if risk_result.factors:
                reasons.extend(risk_result.factors)
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent="unknown",
                tool="input_check",
                trace_id=trace_id,
                correlation_id=corr_id,
            )
            self._publish_security_event(
                agent_id="unknown",
                tool="input_check",
                event_type=EventType.RISK_DETECTION.value,
                severity=EventSeverity.CRITICAL.value if risk_result.severity == RiskLevel.CRITICAL else EventSeverity.HIGH.value,
                decision="BLOCK",
                risk_score=risk_result.score,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=corr_id,
                metadata={"user_input_length": len(user_input), "factors": risk_result.factors},
            )
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if hasattr(self, "metrics_collector") and self.metrics_collector:
                self.metrics_collector.record_decision("BLOCK", duration_ms=duration_ms)
            if hasattr(self, "logger") and self.logger:
                self.logger.log_authz(
                    agent="unknown",
                    tool="input_check",
                    decision="BLOCK",
                    risk_score=risk_result.score,
                    reasons=reasons,
                    correlation_id=corr_id,
                    trace_id=trace_id,
                    latency_ms=duration_ms,
                )
            return dec
        
        reasons = ["Input looks safe"]
        if risk_result.factors:
            reasons.extend(risk_result.factors)

        decision_val = DecisionValue.ALLOW
        if risk_result.severity in (RiskLevel.HIGH, RiskLevel.MEDIUM) and risk_result.score > 50:
            decision_val = DecisionValue.REVIEW

        dec = self._build_decision(
            allowed=(decision_val == DecisionValue.ALLOW),
            decision=decision_val,
            reasons=reasons,
            risk_score=risk_result.score,
            severity=risk_result.severity,
            agent="unknown",
            tool="input_check",
            trace_id=trace_id,
            correlation_id=corr_id,
        )
        self._publish_security_event(
            agent_id="unknown",
            tool="input_check",
            event_type=EventType.INPUT_CHECK.value if decision_val == DecisionValue.ALLOW else EventType.RISK_DETECTION.value,
            severity=EventSeverity.LOW.value if decision_val == DecisionValue.ALLOW else EventSeverity.MEDIUM.value,
            decision=decision_val.value,
            risk_score=risk_result.score,
            evidence=reasons,
            trace_id=trace_id,
            correlation_id=corr_id,
            metadata={"user_input_length": len(user_input), "factors": risk_result.factors},
        )
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        if hasattr(self, "metrics_collector") and self.metrics_collector:
            self.metrics_collector.record_decision(decision_val.value, duration_ms=duration_ms)
        if hasattr(self, "logger") and self.logger:
            self.logger.log_authz(
                agent="unknown",
                tool="input_check",
                decision=decision_val.value,
                risk_score=risk_result.score,
                reasons=reasons,
                correlation_id=corr_id,
                trace_id=trace_id,
                latency_ms=duration_ms,
            )
        return dec

    def authorize(
        self,
        agent: str,
        tool: str,
        arguments: Optional[Dict[str, Any]] = None,
        permissions: Optional[List[str]] = None,
        agent_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> Decision:
        start_time = time.perf_counter()
        from agentshield.observability.correlation import sanitize_correlation_id, generate_trace_id, get_current_correlation_id
        if arguments is None:
            arguments = {}
        if permissions is None:
            permissions = []

        trace_id = trace_id or generate_trace_id()
        raw_corr = correlation_id
        if not raw_corr and isinstance(arguments, dict):
            if "correlation_id" in arguments:
                raw_corr = str(arguments["correlation_id"])
            elif "trace_id" in arguments:
                raw_corr = str(arguments["trace_id"])
        if not raw_corr:
            raw_corr = get_current_correlation_id()
        correlation_id = sanitize_correlation_id(raw_corr)

        # 0. Validate payload argument size limits
        if hasattr(self, "reliability_config") and self.reliability_config:
            from agentshield.reliability.limits import check_arguments_size, PayloadSizeLimitError
            try:
                check_arguments_size(arguments, self.reliability_config.max_arguments_bytes)
            except PayloadSizeLimitError as e:
                reasons = [f"Payload size limit exceeded: {str(e)}"]
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=95.0,
                    severity=RiskLevel.HIGH,
                    agent=agent if isinstance(agent, str) and agent else "unknown",
                    tool=tool if isinstance(tool, str) and tool else "unknown",
                    arguments=None,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=dec.agent,
                    tool=dec.tool,
                    event_type=EventType.SECURITY_FAILURE.value,
                    severity=EventSeverity.HIGH.value,
                    decision="BLOCK",
                    risk_score=95.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"error": "payload_size_limit_exceeded", "limit": self.reliability_config.max_arguments_bytes},
                )
                return self._finalize_decision(dec, start_time)

        tool_rule = self.policy_engine.config.tools.get(tool)
        schema = tool_rule.argument_schema if tool_rule else None

        if self.enforce_secret_references and isinstance(arguments, dict):
            from agentshield.review.store import CREDENTIAL_KEY_PATTERN
            for k, v in arguments.items():
                if CREDENTIAL_KEY_PATTERN.match(str(k)):
                    if not is_secret_reference(v):
                        reasons = [f"Agents must not submit raw credentials for '{k}'; use opaque secret references (e.g. secret_ref://...)"]
                        dec = self._build_decision(
                            allowed=False,
                            decision=DecisionValue.BLOCK,
                            reasons=reasons,
                            risk_score=95.0,
                            severity=RiskLevel.CRITICAL,
                            agent=agent if isinstance(agent, str) and agent else "unknown",
                            tool=tool if isinstance(tool, str) and tool else "unknown",
                            arguments=None,
                            trace_id=trace_id,
                            correlation_id=correlation_id,
                        )
                        self._publish_security_event(
                            agent_id=dec.agent,
                            tool=dec.tool,
                            event_type=EventType.SECURITY_FAILURE.value,
                            severity=EventSeverity.CRITICAL.value,
                            decision="BLOCK",
                            risk_score=95.0,
                            evidence=reasons,
                            trace_id=trace_id,
                            correlation_id=correlation_id,
                            metadata={"attempted_credential_key": str(k)},
                        )
                        return self._finalize_decision(dec, start_time)

        try:
            frozen_args = normalize_and_freeze(arguments, schema=schema)
            action = Action(agent=agent, tool=tool, arguments=frozen_args)
        except (ValueError, TypeError) as e:
            reasons = [f"Malformed request: {str(e)}"]
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=80.0,
                severity=RiskLevel.HIGH,
                agent=agent if isinstance(agent, str) and agent else "unknown",
                tool=tool if isinstance(tool, str) and tool else "unknown",
                arguments=None,
                trace_id=trace_id,
                correlation_id=correlation_id,
            )
            self._publish_security_event(
                agent_id=dec.agent,
                tool=dec.tool,
                event_type=EventType.SECURITY_FAILURE.value,
                severity=EventSeverity.HIGH.value,
                decision="BLOCK",
                risk_score=80.0,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata={"error": str(e)},
            )
            return self._finalize_decision(dec, start_time)

        # 0. Check paused status
        if self.is_agent_paused(action.agent):
            reasons = [f"Agent '{action.agent}' is currently paused by incident controls"]
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=100.0,
                severity=RiskLevel.CRITICAL,
                agent=action.agent,
                tool=action.tool,
                arguments=action.arguments,
                trace_id=trace_id,
                correlation_id=correlation_id,
            )
            self._publish_security_event(
                agent_id=action.agent,
                tool=action.tool,
                event_type=EventType.SECURITY_FAILURE.value,
                severity=EventSeverity.CRITICAL.value,
                decision="BLOCK",
                risk_score=100.0,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata={"paused": True},
            )
            return self._finalize_decision(dec, start_time)

        # 0.5 Authenticate agent if keys are configured
        if action.agent in self.agent_keys:
            stored_hash = self.agent_keys[action.agent]
            salt = self._agent_salts.get(action.agent)
            authenticated = False
            if agent_key and salt:
                computed_hash = _hash_credential(agent_key, salt)
                if hmac.compare_digest(stored_hash, computed_hash):
                    authenticated = True
                elif action.agent in self._retired_agent_keys:
                    for prev_salt, prev_hash in self._retired_agent_keys[action.agent]:
                        if hmac.compare_digest(prev_hash, _hash_credential(agent_key, prev_salt)):
                            authenticated = True
                            break
            elif agent_key and not salt:
                computed = hashlib.sha256(agent_key.encode("utf-8")).hexdigest()
                if hmac.compare_digest(stored_hash, computed):
                    authenticated = True

            if not authenticated:
                reasons = [f"Authentication failed: Invalid or missing key for agent '{action.agent}'"]
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=95.0,
                    severity=RiskLevel.CRITICAL,
                    agent=action.agent,
                    tool=action.tool,
                    arguments=action.arguments,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=action.agent,
                    tool=action.tool,
                    event_type=EventType.SECURITY_FAILURE.value,
                    severity=EventSeverity.CRITICAL.value,
                    decision="BLOCK",
                    risk_score=95.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"reason": "agent_auth_failure"},
                )
                return self._finalize_decision(dec, start_time)

        # 0.75 Reliability controls: Session budget, Rate limiting, Loop detection
        if hasattr(self, "budget_tracker") and self.budget_tracker and hasattr(self, "reliability_config") and self.reliability_config:
            from agentshield.reliability.limits import ToolCallBudgetExceededError
            try:
                self.budget_tracker.check_and_increment(
                    context_id=correlation_id,
                    limit=self.reliability_config.max_tool_calls_per_session,
                )
            except ToolCallBudgetExceededError as e:
                reasons = [f"Session tool execution budget exceeded: limit of {self.reliability_config.max_tool_calls_per_session} calls reached"]
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=95.0,
                    severity=RiskLevel.HIGH,
                    agent=action.agent,
                    tool=action.tool,
                    arguments=action.arguments,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=action.agent,
                    tool=action.tool,
                    event_type=EventType.POLICY_VIOLATION.value,
                    severity=EventSeverity.HIGH.value,
                    decision="BLOCK",
                    risk_score=95.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"reason": "session_budget_exceeded", "limit": self.reliability_config.max_tool_calls_per_session},
                )
                return self._finalize_decision(dec, start_time)

        if getattr(self, "rate_limiter", None) is not None and getattr(self, "reliability_config", None):
            from agentshield.reliability.config import parse_rate_limit
            # Check agent rate limit
            ag_max, ag_win = parse_rate_limit(self.reliability_config.rate_limit_agent)
            ag_res = self.rate_limiter.check(f"agent:{action.agent}", ag_max, ag_win)
            if not ag_res.allowed:
                reasons = [f"Rate limit exceeded for agent '{action.agent}': limit {ag_max}/{ag_win:.0f}s exceeded (retry after {ag_res.retry_after:.1f}s)"]
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=90.0,
                    severity=RiskLevel.HIGH,
                    agent=action.agent,
                    tool=action.tool,
                    arguments=action.arguments,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=action.agent,
                    tool=action.tool,
                    event_type=EventType.RATE_LIMIT_EXCEEDED.value,
                    severity=EventSeverity.HIGH.value,
                    decision="BLOCK",
                    risk_score=90.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"rate_limit_scope": "agent", "retry_after": ag_res.retry_after},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_rate_limit_hit("agent")
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_rate_limit("agent", f"agent:{action.agent}", ag_max, ag_win, ag_res.retry_after, correlation_id=correlation_id)
                return self._finalize_decision(dec, start_time)

            # Check tool rate limit
            tl_max, tl_win = parse_rate_limit(self.reliability_config.rate_limit_tool)
            tl_res = self.rate_limiter.check(f"tool:{action.agent}:{action.tool}", tl_max, tl_win)
            if not tl_res.allowed:
                reasons = [f"Rate limit exceeded for tool '{action.tool}': limit {tl_max}/{tl_win:.0f}s exceeded (retry after {tl_res.retry_after:.1f}s)"]
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=90.0,
                    severity=RiskLevel.HIGH,
                    agent=action.agent,
                    tool=action.tool,
                    arguments=action.arguments,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=action.agent,
                    tool=action.tool,
                    event_type=EventType.RATE_LIMIT_EXCEEDED.value,
                    severity=EventSeverity.HIGH.value,
                    decision="BLOCK",
                    risk_score=90.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"rate_limit_scope": "tool", "retry_after": tl_res.retry_after},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_rate_limit_hit("tool")
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_rate_limit("tool", f"tool:{action.agent}:{action.tool}", tl_max, tl_win, tl_res.retry_after, correlation_id=correlation_id)
                return self._finalize_decision(dec, start_time)

        if getattr(self, "loop_detector", None) is not None:
            loop_res = self.loop_detector.check(correlation_id, action.tool, action.arguments)
            if loop_res.is_loop:
                reasons = loop_res.reasons
                dec = self._build_decision(
                    allowed=False,
                    decision=DecisionValue.BLOCK,
                    reasons=reasons,
                    risk_score=95.0,
                    severity=RiskLevel.HIGH,
                    agent=action.agent,
                    tool=action.tool,
                    arguments=action.arguments,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                )
                self._publish_security_event(
                    agent_id=action.agent,
                    tool=action.tool,
                    event_type=EventType.LOOP_DETECTED.value,
                    severity=EventSeverity.HIGH.value,
                    decision="BLOCK",
                    risk_score=95.0,
                    evidence=reasons,
                    trace_id=trace_id,
                    correlation_id=correlation_id,
                    metadata={"loop_type": loop_res.loop_type, "count": loop_res.count, "pattern": loop_res.pattern_description},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_loop_detected(loop_res.loop_type or "consecutive")
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_loop(action.agent, action.tool, loop_res.loop_type or "consecutive", {"count": loop_res.count, "pattern": loop_res.pattern_description}, correlation_id=correlation_id)
                return self._finalize_decision(dec, start_time)

        # 1. Deterministic Policy Evaluation (fails closed)
        policy_results = self.policy_engine.evaluate(action, permissions)
        failed_policies = [p for p in policy_results if not p.passed]

        # 2. Risk Evaluation
        risk_result = self.risk_engine.evaluate(action=action, permissions=permissions)

        # Policy failure ALWAYS takes absolute precedence -> BLOCK (risk never overrides policy denial)
        if failed_policies:
            reasons = [f"Policy failed: {p.rule} - {p.reason}" for p in failed_policies]
            if risk_result.factors:
                reasons.extend(risk_result.factors)
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=max(risk_result.score, 80.0),
                severity=RiskLevel.HIGH if risk_result.severity in (RiskLevel.LOW, RiskLevel.MEDIUM) else risk_result.severity,
                agent=action.agent,
                tool=action.tool,
                arguments=action.arguments,
                trace_id=trace_id,
                correlation_id=correlation_id,
            )
            self._publish_security_event(
                agent_id=action.agent,
                tool=action.tool,
                event_type=EventType.POLICY_VIOLATION.value,
                severity=EventSeverity.HIGH.value if dec.severity == RiskLevel.HIGH else EventSeverity.CRITICAL.value,
                decision="BLOCK",
                risk_score=dec.risk_score,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata={"failed_rules": [p.rule for p in failed_policies], "arguments": action.arguments},
            )
            return self._finalize_decision(dec, start_time)

        # 3. Policy passed: risk can elevate ALLOW to REVIEW or BLOCK
        if risk_result.severity == RiskLevel.CRITICAL:
            reasons = list(risk_result.factors) if risk_result.factors else ["Risk score critical threshold exceeded"]
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.BLOCK,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent=action.agent,
                tool=action.tool,
                arguments=action.arguments,
                trace_id=trace_id,
                correlation_id=correlation_id,
            )
            self._publish_security_event(
                agent_id=action.agent,
                tool=action.tool,
                event_type=EventType.RISK_DETECTION.value,
                severity=EventSeverity.CRITICAL.value,
                decision="BLOCK",
                risk_score=risk_result.score,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata={"factors": risk_result.factors, "arguments": action.arguments},
            )
            return self._finalize_decision(dec, start_time)
        elif risk_result.severity == RiskLevel.HIGH:
            reasons = list(risk_result.factors) if risk_result.factors else ["Risk score elevated to review threshold"]
            dec = self._build_decision(
                allowed=False,
                decision=DecisionValue.REVIEW,
                reasons=reasons,
                risk_score=risk_result.score,
                severity=risk_result.severity,
                agent=action.agent,
                tool=action.tool,
                arguments=action.arguments,
                trace_id=trace_id,
                correlation_id=correlation_id,
            )
            # Queue for approval with expires_at timestamp
            review_id = f"rev_{uuid.uuid4().hex[:10]}"
            dec.review_id = review_id
            now = time.time()
            idempotency_key = None
            if isinstance(action.arguments, dict):
                idempotency_key = action.arguments.get("idempotency_key")
            self.review_store.enqueue_review(
                review_id=review_id,
                agent=action.agent,
                tool=action.tool,
                arguments=action.arguments,
                permissions=permissions,
                decision=dec,
                created_at=now,
                expires_at=now + self.review_ttl_seconds,
                idempotency_key=idempotency_key,
            )
            self._publish_security_event(
                agent_id=action.agent,
                tool=action.tool,
                event_type=EventType.REVIEW_ACTION.value,
                severity=EventSeverity.HIGH.value,
                decision="REVIEW",
                risk_score=risk_result.score,
                evidence=reasons,
                trace_id=trace_id,
                correlation_id=correlation_id,
                metadata={"review_id": review_id, "action": "enqueue", "arguments": action.arguments},
            )
            return self._finalize_decision(dec, start_time)

        reasons = ["Action authorized"]
        if risk_result.factors:
            reasons.extend(risk_result.factors)

        dec = self._build_decision(
            allowed=True,
            decision=DecisionValue.ALLOW,
            reasons=reasons,
            risk_score=risk_result.score,
            severity=risk_result.severity,
            agent=action.agent,
            tool=action.tool,
            arguments=action.arguments,
            trace_id=trace_id,
            correlation_id=correlation_id,
        )
        self._publish_security_event(
            agent_id=action.agent,
            tool=action.tool,
            event_type=EventType.AUTHORIZATION_DECISION.value,
            severity=EventSeverity.LOW.value,
            decision="ALLOW",
            risk_score=risk_result.score,
            evidence=reasons,
            trace_id=trace_id,
            correlation_id=correlation_id,
            metadata={"arguments": action.arguments},
        )
        return self._finalize_decision(dec, start_time)

    def execute(
        self,
        agent: str,
        tool: str,
        arguments: Optional[Dict[str, Any]] = None,
        permissions: Optional[List[str]] = None,
        agent_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> ExecutionResult:
        decision = self.authorize(
            agent, tool, arguments, permissions, agent_key=agent_key,
            correlation_id=correlation_id, trace_id=trace_id,
        )
        policy_hash = self.policy_engine.version_hash
        frozen_args = decision.arguments
        
        if decision.decision != DecisionValue.ALLOW or not decision.allowed:
            result = ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None)
            if self.audit_store:
                try:
                    self.audit_store.log_decision(
                        decision,
                        frozen_args,
                        execution_status="not_executed",
                        policy_version_hash=policy_hash
                    )
                except Exception:
                    pass
            self._publish_security_event(
                agent_id=decision.agent,
                tool=decision.tool,
                event_type=EventType.EXECUTION_OUTCOME.value,
                severity=EventSeverity.LOW.value if decision.decision == DecisionValue.REVIEW else EventSeverity.MEDIUM.value,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                evidence=decision.reasons,
                trace_id=decision.trace_id,
                correlation_id=decision.correlation_id,
                metadata={"execution_status": "not_executed", "arguments": frozen_args},
            )
            if hasattr(self, "metrics_collector") and self.metrics_collector:
                self.metrics_collector.record_execution("not_executed", duration_ms=0.0)
            if hasattr(self, "logger") and self.logger:
                self.logger.log_execution(
                    agent=decision.agent,
                    tool=decision.tool,
                    status="not_executed",
                    correlation_id=decision.correlation_id,
                    trace_id=decision.trace_id,
                    latency_ms=0.0,
                    arguments=frozen_args,
                )
            return result
            
        idempotency_key = None
        if isinstance(frozen_args, dict):
            idempotency_key = frozen_args.get("idempotency_key")
        return self._execute_approved(decision, agent, tool, frozen_args, idempotency_key=idempotency_key)

    def _execute_approved(
        self,
        decision: Decision,
        agent: str,
        tool: str,
        arguments: Optional[Any],
        idempotency_key: Optional[str] = None,
    ) -> ExecutionResult:
        policy_hash = self.policy_engine.version_hash
        start_exec = time.perf_counter()
        registered_tool = self.registry.get_tool(tool)
        if not registered_tool:
            err = f"Tool {tool} not found in registry"
            result = ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None, error=err)
            if self.audit_store:
                self.audit_store.log_decision(
                    decision,
                    arguments,
                    execution_status="not_executed",
                    error=err,
                    policy_version_hash=policy_hash
                )
            self._publish_security_event(
                agent_id=agent,
                tool=tool,
                event_type=EventType.EXECUTION_OUTCOME.value,
                severity=EventSeverity.HIGH.value,
                decision="BLOCK",
                risk_score=decision.risk_score,
                evidence=[err],
                trace_id=decision.trace_id,
                correlation_id=decision.correlation_id,
                metadata={"execution_status": "not_executed", "error": err, "arguments": arguments},
            )
            if hasattr(self, "metrics_collector") and self.metrics_collector:
                self.metrics_collector.record_execution("error", duration_ms=0.0)
            if hasattr(self, "logger") and self.logger:
                self.logger.log_execution(
                    agent=agent,
                    tool=tool,
                    status="error",
                    correlation_id=decision.correlation_id,
                    trace_id=decision.trace_id,
                    latency_ms=0.0,
                    error=err,
                    arguments=arguments,
                )
            return result

        executed = False
        res = None
        try:
            # Safe execution adapter: pass a clean defensive copy to the callable
            # so the callable can freely modify its arguments without mutating the validated frozen snapshot
            # and ensure idempotency key reaches downstream tool.
            res = self._safe_execute_tool(registered_tool, arguments, idempotency_key=idempotency_key)
            executed = True
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            result = ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
            try:
                if self.audit_store:
                    self.audit_store.log_decision(
                        decision,
                        arguments,
                        execution_status="executed",
                        policy_version_hash=policy_hash
                    )
                self._publish_security_event(
                    agent_id=agent,
                    tool=tool,
                    event_type=EventType.EXECUTION_OUTCOME.value,
                    severity=EventSeverity.LOW.value,
                    decision="ALLOW",
                    risk_score=decision.risk_score,
                    evidence=["Tool executed successfully"],
                    trace_id=decision.trace_id,
                    correlation_id=decision.correlation_id,
                    metadata={"execution_status": "executed", "arguments": arguments},
                )
                if hasattr(self, "metrics_collector") and self.metrics_collector:
                    self.metrics_collector.record_execution("executed", duration_ms=duration_ms)
                if hasattr(self, "logger") and self.logger:
                    self.logger.log_execution(
                        agent=agent,
                        tool=tool,
                        status="executed",
                        correlation_id=decision.correlation_id,
                        trace_id=decision.trace_id,
                        latency_ms=duration_ms,
                        arguments=arguments,
                    )
            except Exception:
                pass
            return result
        except Exception as e:
            if executed:
                return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            err_msg = str(e)
            is_timeout = "timeout" in err_msg.lower() or "timed out" in err_msg.lower()
            status_str = "timeout" if is_timeout else "error"
            result = ExecutionResult(decision=decision, execution_status=ExecutionStatus.ERROR, tool_result=None, error=err_msg)
            if self.audit_store:
                try:
                    self.audit_store.log_decision(
                        decision,
                        arguments,
                        execution_status="error",
                        error=err_msg,
                        policy_version_hash=policy_hash
                    )
                except Exception:
                    pass
            self._publish_security_event(
                agent_id=agent,
                tool=tool,
                event_type=EventType.EXECUTION_OUTCOME.value,
                severity=EventSeverity.HIGH.value,
                decision="ERROR",
                risk_score=decision.risk_score,
                evidence=[f"Execution error: {err_msg}"],
                trace_id=decision.trace_id,
                correlation_id=decision.correlation_id,
                metadata={"execution_status": "error", "error": err_msg, "arguments": arguments},
            )
            if hasattr(self, "metrics_collector") and self.metrics_collector:
                self.metrics_collector.record_execution(status_str, duration_ms=duration_ms)
            if hasattr(self, "logger") and self.logger:
                self.logger.log_execution(
                    agent=agent,
                    tool=tool,
                    status=status_str,
                    correlation_id=decision.correlation_id,
                    trace_id=decision.trace_id,
                    latency_ms=duration_ms,
                    error=err_msg,
                    arguments=arguments,
                )
            return result

    def _safe_execute_tool(
        self,
        registered_tool: RegisteredTool,
        arguments: Optional[Any],
        idempotency_key: Optional[str] = None,
    ) -> Any:
        """Safe execution adapter: unfreezes arguments defensively so registered tools
        can safely read or mutate their local argument copy without affecting validated snapshots.
        Ensures the exact same idempotency_key reaches downstream tool callables on execution and retry.
        Resolves opaque secret references via the executor's secret provider right before invocation.
        """
        execution_args = unfreeze_value(arguments) if arguments is not None else {}

        # Resolve opaque secret references using executor-owned provider
        if self.secret_provider is not None:
            execution_args = resolve_secret_references(execution_args, self.secret_provider)

        if idempotency_key and isinstance(execution_args, dict):
            if "idempotency_key" not in execution_args:
                execution_args["idempotency_key"] = idempotency_key

        from agentshield.reliability.limits import CancellationToken, SafeExecutionContext, execute_with_timeout

        cancellation_token = CancellationToken()
        safe_context = SafeExecutionContext(tool_name=registered_tool.name, cancellation_token=cancellation_token)

        # Inject cooperative cancellation and context for dict arguments
        if isinstance(execution_args, dict):
            execution_args["_cancellation_token"] = cancellation_token
            execution_args["_safe_context"] = safe_context

        def _invoke():
            call_fn = None
            args_to_pass = ()
            kwargs_to_pass = {}
            try:
                sig = inspect.signature(registered_tool.callable_func)
                params = list(sig.parameters.values())
                param_names = {p.name for p in params}
                has_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

                if not params:
                    call_fn = registered_tool.callable_func
                    args_to_pass = ()
                    kwargs_to_pass = {}
                elif isinstance(execution_args, dict) and params:
                    first_param = params[0].name
                    if first_param in ("args", "arguments", "payload", "data"):
                        kw = {}
                        if "context" in param_names:
                            kw["context"] = safe_context
                        if "cancellation_token" in param_names:
                            kw["cancellation_token"] = cancellation_token
                        if (any(p.name == "idempotency_key" for p in params) or has_var_keyword) and idempotency_key:
                            kw["idempotency_key"] = idempotency_key
                        call_fn = registered_tool.callable_func
                        args_to_pass = (execution_args,)
                        kwargs_to_pass = kw
                    else:
                        call_kwargs = {}
                        for k, v in execution_args.items():
                            if k in ("_cancellation_token", "_safe_context") and not has_var_keyword and k not in param_names:
                                continue
                            call_kwargs[k] = v

                        if "cancellation_token" in param_names and "cancellation_token" not in call_kwargs:
                            call_kwargs["cancellation_token"] = cancellation_token
                        if "context" in param_names and "context" not in call_kwargs:
                            call_kwargs["context"] = safe_context

                        if (
                            has_var_keyword
                            or len(params) > 1
                            or (len(params) == 1 and params[0].name in call_kwargs)
                        ):
                            call_fn = registered_tool.callable_func
                            args_to_pass = ()
                            kwargs_to_pass = call_kwargs
                        elif (any(p.name == "idempotency_key" for p in params) or has_var_keyword) and idempotency_key:
                            call_fn = registered_tool.callable_func
                            args_to_pass = (execution_args,)
                            kwargs_to_pass = {"idempotency_key": idempotency_key}
            except Exception:
                pass

            if call_fn is not None:
                return call_fn(*args_to_pass, **kwargs_to_pass)

            return registered_tool.callable_func(execution_args)

        timeout_sec = (
            self.reliability_config.max_tool_execution_seconds
            if hasattr(self, "reliability_config") and self.reliability_config
            else 30.0
        )
        return execute_with_timeout(
            _invoke,
            timeout_seconds=timeout_sec,
            tool_name=registered_tool.name,
            cancellation_token=cancellation_token,
        )

    def _build_decision(
        self,
        allowed: bool,
        decision: DecisionValue,
        reasons: list[str],
        risk_score: float,
        severity: RiskLevel,
        agent: str,
        tool: str,
        arguments: Optional[Any] = None,
        trace_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        review_id: Optional[str] = None,
    ) -> Decision:
        return Decision(
            allowed=allowed,
            decision=decision,
            reasons=reasons,
            risk_score=risk_score,
            severity=severity,
            agent=agent,
            tool=tool,
            arguments=arguments,
            trace_id=trace_id,
            correlation_id=correlation_id,
            review_id=review_id,
        )
