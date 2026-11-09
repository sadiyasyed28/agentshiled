"""AgentShield LangChain Integration.

Provides an adapter to protect LangChain tools with AgentShield's runtime
security policy engine, parameter validation, risk evaluation, and audit logging.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from pydantic import ConfigDict, BaseModel, PrivateAttr

try:
    from langchain_core.tools import BaseTool, StructuredTool, tool
except ImportError as err:
    raise ImportError(
        "The AgentShield LangChain integration requires 'langchain-core'. "
        "Install it with: pip install 'agentshield[langchain]'"
    ) from err

from agentshield.models import (
    Decision,
    DecisionValue,
    RiskLevel,
    unfreeze_value,
)
from agentshield.events import (
    EventSeverity,
    EventType,
)
from agentshield.shield import (
    ExecutionResult,
    ExecutionStatus,
    Shield,
    ToolBlockedError,
    ToolReviewRequiredError,
)


class AgentShieldTool(BaseTool):
    """LangChain BaseTool wrapper that enforces AgentShield security policies,
    argument validation, risk evaluation, and audit logging.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    _underlying_tool: Any = PrivateAttr(default=None)
    shield: Any
    agent: Optional[str] = None
    permissions: Optional[List[str]] = None
    correlation_id: Optional[str] = None
    raise_on_blocked: bool = True
    read_only: bool = False
    idempotent: bool = False
    call_count: int = 0

    def __init__(self, **kwargs: Any) -> None:
        raw_tool = kwargs.pop("wrapped_tool", None) or kwargs.pop("_underlying_tool", None)
        super().__init__(**kwargs)
        if raw_tool is not None:
            self._underlying_tool = raw_tool

    def __getattr__(self, name: str) -> Any:
        if name in ("wrapped_tool", "__wrapped__", "raw_tool", "underlying_tool"):
            raise PermissionError(
                f"Direct access to '{name}' is forbidden by AgentShield to prevent security policy bypass. "
                "Invoke the protected tool directly."
            )
        return super().__getattr__(name)

    @classmethod
    def from_tool(
        cls,
        tool: Any,
        shield: Any,
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
    ) -> AgentShieldTool:
        """Wrap an existing LangChain tool or callable with AgentShield protections."""
        return protect_langchain_tool(
            tool=tool,
            shield=shield,
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

    def _to_args_and_kwargs(
        self, tool_input: Union[str, Dict[str, Any]], tool_call_id: Optional[str] = None
    ) -> Tuple[Tuple[Any, ...], Dict[str, Any]]:
        extra_ctrl = {}
        if isinstance(tool_input, dict):
            clean_input = dict(tool_input)
            for k in ("_agent", "_permissions", "_correlation_id"):
                if k in clean_input:
                    extra_ctrl[k] = clean_input.pop(k)
            tool_input = clean_input

        tool_args, tool_kwargs = super()._to_args_and_kwargs(tool_input, tool_call_id)
        if extra_ctrl:
            tool_kwargs.update(extra_ctrl)
        return tool_args, tool_kwargs

    def _extract_call_context(
        self,
        args: Tuple[Any, ...],
        kwargs: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[List[str]], Optional[str], Dict[str, Any]]:
        clean_kwargs = dict(kwargs)
        effective_agent = clean_kwargs.pop("_agent", self.agent)
        effective_permissions = clean_kwargs.pop("_permissions", self.permissions)
        effective_correlation_id = clean_kwargs.pop("_correlation_id", self.correlation_id)

        if clean_kwargs:
            arguments = dict(clean_kwargs)
            if args:
                field_names = list(self.args.keys()) if self.args else []
                for i, val in enumerate(args):
                    param_name = field_names[i] if i < len(field_names) else f"arg_{i}"
                    if param_name not in arguments:
                        arguments[param_name] = val
        elif args:
            if len(args) == 1 and isinstance(args[0], dict):
                arguments = dict(args[0])
            elif len(args) == 1:
                field_names = list(self.args.keys()) if self.args else []
                if len(field_names) == 1:
                    arguments = {field_names[0]: args[0]}
                else:
                    arguments = {"input": args[0]}
            else:
                field_names = list(self.args.keys()) if self.args else []
                arguments = {}
                for i, val in enumerate(args):
                    param_name = field_names[i] if i < len(field_names) else f"arg_{i}"
                    arguments[param_name] = val
        else:
            arguments = {}

        return effective_agent, effective_permissions, effective_correlation_id, arguments

    def _execute_tool_sync(self, exec_args: Any) -> Any:
        try:
            return self._underlying_tool.invoke(exec_args)
        except TypeError:
            if isinstance(exec_args, dict) and len(exec_args) == 1:
                return self._underlying_tool.invoke(next(iter(exec_args.values())))
            raise

    async def _execute_tool_async(self, exec_args: Any) -> Any:
        try:
            return await self._underlying_tool.ainvoke(exec_args)
        except TypeError:
            if isinstance(exec_args, dict) and len(exec_args) == 1:
                return await self._underlying_tool.ainvoke(next(iter(exec_args.values())))
            raise

    def _log_and_audit_success(
        self,
        decision: Decision,
        agent_name: str,
        exec_args: Any,
        duration_ms: float,
        policy_hash: str,
    ) -> None:
        if self.shield.audit_store:
            self.shield.audit_store.log_decision(
                decision,
                exec_args,
                execution_status="executed",
                policy_version_hash=policy_hash,
            )
        self.shield._publish_security_event(
            agent_id=agent_name,
            tool=self.name,
            event_type=EventType.EXECUTION_OUTCOME.value,
            severity=EventSeverity.LOW.value,
            decision="ALLOW",
            risk_score=decision.risk_score,
            evidence=["Tool executed successfully via LangChain adapter"],
            trace_id=decision.trace_id,
            correlation_id=decision.correlation_id,
            metadata={"execution_status": "executed", "arguments": exec_args},
        )
        if hasattr(self.shield, "metrics_collector") and self.shield.metrics_collector:
            self.shield.metrics_collector.record_execution("executed", duration_ms=duration_ms)
        if hasattr(self.shield, "logger") and self.shield.logger:
            self.shield.logger.log_execution(
                agent=agent_name,
                tool=self.name,
                status="executed",
                correlation_id=decision.correlation_id,
                trace_id=decision.trace_id,
                latency_ms=duration_ms,
                arguments=exec_args,
            )

    def _log_and_audit_error(
        self,
        decision: Decision,
        agent_name: str,
        exec_args: Any,
        err_msg: str,
        duration_ms: float,
        policy_hash: str,
    ) -> None:
        is_timeout = "timeout" in err_msg.lower() or "timed out" in err_msg.lower()
        status_str = "timeout" if is_timeout else "error"
        if self.shield.audit_store:
            self.shield.audit_store.log_decision(
                decision,
                exec_args,
                execution_status="error",
                error=err_msg,
                policy_version_hash=policy_hash,
            )
        self.shield._publish_security_event(
            agent_id=agent_name,
            tool=self.name,
            event_type=EventType.EXECUTION_OUTCOME.value,
            severity=EventSeverity.HIGH.value,
            decision="ERROR",
            risk_score=decision.risk_score,
            evidence=[f"LangChain tool execution error: {err_msg}"],
            trace_id=decision.trace_id,
            correlation_id=decision.correlation_id,
            metadata={"execution_status": "error", "error": err_msg, "arguments": exec_args},
        )
        if hasattr(self.shield, "metrics_collector") and self.shield.metrics_collector:
            self.shield.metrics_collector.record_execution(status_str, duration_ms=duration_ms)
        if hasattr(self.shield, "logger") and self.shield.logger:
            self.shield.logger.log_execution(
                agent=agent_name,
                tool=self.name,
                status=status_str,
                correlation_id=decision.correlation_id,
                trace_id=decision.trace_id,
                latency_ms=duration_ms,
                error=err_msg,
                arguments=exec_args,
            )

    def _handle_non_allow(self, decision: Decision, effective_agent: Optional[str], arguments: Dict[str, Any]) -> Any:
        policy_hash = getattr(self.shield.policy_engine, "version_hash", "none")
        agent_name = effective_agent or "unknown"
        if decision.decision == DecisionValue.REVIEW:
            rev_id = getattr(decision, "review_id", None)
            if self.shield.audit_store:
                self.shield.audit_store.log_decision(
                    decision,
                    arguments,
                    execution_status="review_pending",
                    policy_version_hash=policy_hash,
                )
            self.shield._publish_security_event(
                agent_id=agent_name,
                tool=self.name,
                event_type=EventType.EXECUTION_OUTCOME.value,
                severity=EventSeverity.LOW.value,
                decision="REVIEW",
                risk_score=decision.risk_score,
                evidence=decision.reasons,
                trace_id=decision.trace_id,
                correlation_id=decision.correlation_id,
                metadata={"execution_status": "review_pending", "review_id": rev_id, "arguments": arguments},
            )
            if hasattr(self.shield, "metrics_collector") and self.shield.metrics_collector:
                self.shield.metrics_collector.record_execution("review_pending", duration_ms=0.0)
            if self.raise_on_blocked:
                raise ToolReviewRequiredError(
                    f"Tool '{self.name}' for agent '{agent_name}' requires human review approval"
                    f"{f' (review_id: {rev_id})' if rev_id else ''}",
                    decision=decision,
                    tool_name=self.name,
                    agent=agent_name,
                    review_id=rev_id,
                )
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None)
        else:
            # BLOCK or other rejection
            if self.shield.audit_store:
                self.shield.audit_store.log_decision(
                    decision,
                    arguments,
                    execution_status="not_executed",
                    policy_version_hash=policy_hash,
                )
            self.shield._publish_security_event(
                agent_id=agent_name,
                tool=self.name,
                event_type=EventType.EXECUTION_OUTCOME.value,
                severity=EventSeverity.HIGH.value if decision.severity == RiskLevel.HIGH else EventSeverity.CRITICAL.value,
                decision="BLOCK",
                risk_score=decision.risk_score,
                evidence=decision.reasons,
                trace_id=decision.trace_id,
                correlation_id=decision.correlation_id,
                metadata={"execution_status": "not_executed", "arguments": arguments},
            )
            if hasattr(self.shield, "metrics_collector") and self.shield.metrics_collector:
                self.shield.metrics_collector.record_execution("blocked", duration_ms=0.0)
            if self.raise_on_blocked:
                reasons_str = "; ".join(decision.reasons) if decision.reasons else "Invocation blocked by security policy"
                raise ToolBlockedError(
                    f"Tool '{self.name}' for agent '{agent_name}' blocked: {reasons_str}",
                    decision=decision,
                    tool_name=self.name,
                    agent=agent_name,
                )
            return ExecutionResult(decision=decision, execution_status=ExecutionStatus.NOT_EXECUTED, tool_result=None)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        effective_agent, effective_permissions, effective_correlation_id, arguments = self._extract_call_context(args, kwargs)

        decision = self.shield.authorize(
            agent=effective_agent,
            tool=self.name,
            arguments=arguments,
            permissions=effective_permissions,
            correlation_id=effective_correlation_id,
        )

        if decision.decision != DecisionValue.ALLOW or not decision.allowed:
            return self._handle_non_allow(decision, effective_agent, arguments)

        policy_hash = getattr(self.shield.policy_engine, "version_hash", "none")
        agent_name = effective_agent or "unknown"
        frozen_args = decision.arguments
        exec_args = unfreeze_value(frozen_args) if frozen_args is not None else arguments

        start_exec = time.perf_counter()
        try:
            res = self._execute_tool_sync(exec_args)
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            self.call_count += 1
            self._log_and_audit_success(decision, agent_name, exec_args, duration_ms, policy_hash)
            if not self.raise_on_blocked:
                return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
            return res
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            self._log_and_audit_error(decision, agent_name, exec_args, str(exc), duration_ms, policy_hash)
            raise

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        effective_agent, effective_permissions, effective_correlation_id, arguments = self._extract_call_context(args, kwargs)

        decision = self.shield.authorize(
            agent=effective_agent,
            tool=self.name,
            arguments=arguments,
            permissions=effective_permissions,
            correlation_id=effective_correlation_id,
        )

        if decision.decision != DecisionValue.ALLOW or not decision.allowed:
            return self._handle_non_allow(decision, effective_agent, arguments)

        policy_hash = getattr(self.shield.policy_engine, "version_hash", "none")
        agent_name = effective_agent or "unknown"
        frozen_args = decision.arguments
        exec_args = unfreeze_value(frozen_args) if frozen_args is not None else arguments

        start_exec = time.perf_counter()
        try:
            res = await self._execute_tool_async(exec_args)
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            self.call_count += 1
            self._log_and_audit_success(decision, agent_name, exec_args, duration_ms, policy_hash)
            if not self.raise_on_blocked:
                return ExecutionResult(decision=decision, execution_status=ExecutionStatus.EXECUTED, tool_result=res)
            return res
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_exec) * 1000.0
            self._log_and_audit_error(decision, agent_name, exec_args, str(exc), duration_ms, policy_hash)
            raise


def protect_langchain_tool(
    tool: Any,
    shield: Any,
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
) -> AgentShieldTool:
    """Wraps a LangChain BaseTool (or callable) with AgentShield security policy enforcement.

    Parameters:
        tool: A LangChain BaseTool, StructuredTool, or callable.
        shield: The AgentShield runtime instance.
        agent: The default agent identifier bound to this tool invocation.
        name: Override tool name (defaults to tool.name or func.__name__).
        description: Override description (defaults to tool.description or func.__doc__).
        permissions: Permissions required to invoke this tool.
        correlation_id: Default correlation/session ID.
        raise_on_blocked: If True (default), raises ToolBlockedError or ToolReviewRequiredError.
        read_only: Flag indicating whether tool is read-only.
        idempotent: Flag indicating whether tool is idempotent.
        guarantees_deduplication: Flag indicating whether tool guarantees deduplication.
        metadata: Custom metadata dictionary.
    """
    if not isinstance(tool, BaseTool):
        if callable(tool):
            func_kwargs = {}
            if name:
                func_kwargs["name"] = name
            doc_str = description or getattr(tool, "__doc__", None) or f"Tool {getattr(tool, '__name__', 'unnamed')}"
            func_kwargs["description"] = doc_str
            tool = StructuredTool.from_function(tool, **func_kwargs)
        else:
            raise TypeError(f"Expected a LangChain BaseTool or callable, got {type(tool)}")

    tool_name = name or getattr(tool, "name", None) or getattr(tool, "__name__", "unnamed_tool")
    tool_desc = description or getattr(tool, "description", None) or getattr(tool, "__doc__", "") or ""
    tool_args_schema = getattr(tool, "args_schema", None)
    tool_return_direct = getattr(tool, "return_direct", False)
    tool_tags = getattr(tool, "tags", None)
    tool_meta = dict(getattr(tool, "metadata", None) or {})
    if metadata:
        tool_meta.update(metadata)

    wrapped = AgentShieldTool(
        name=tool_name,
        description=tool_desc,
        args_schema=tool_args_schema,
        return_direct=tool_return_direct,
        tags=tool_tags,
        metadata=tool_meta,
        wrapped_tool=tool,
        shield=shield,
        agent=agent,
        permissions=permissions,
        correlation_id=correlation_id,
        raise_on_blocked=raise_on_blocked,
        read_only=read_only,
        idempotent=idempotent,
    )

    # Register with shield's tool registry to enable policy recognition and review queue execution
    def _registry_callable(arguments: Any, **kwargs: Any) -> Any:
        exec_args = unfreeze_value(arguments) if arguments is not None else {}
        try:
            return tool.invoke(exec_args)
        except (NotImplementedError, TypeError):
            try:
                return asyncio.run(tool.ainvoke(exec_args))
            except Exception:
                if isinstance(exec_args, dict) and len(exec_args) == 1:
                    return tool.invoke(next(iter(exec_args.values())))
                raise

    if hasattr(shield, "registry") and shield.registry is not None:
        shield.registry.register(
            name=tool_name,
            callable_func=_registry_callable,
            metadata=tool_meta,
            required_permissions=permissions,
            idempotent=idempotent,
            read_only=read_only,
            guarantees_deduplication=guarantees_deduplication,
        )

    return wrapped


__all__ = [
    "AgentShieldTool",
    "protect_langchain_tool",
]
