"""AgentShield CrewAI Integration.

Provides an adapter to protect CrewAI tools with AgentShield's runtime
security policy engine, parameter validation, risk evaluation, and audit logging.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from pydantic import ConfigDict, BaseModel, Field

# Lazy dependency resolution for CrewAI BaseTool
_CrewAIBaseTool = None
if "crewai.tools" in sys.modules and hasattr(sys.modules["crewai.tools"], "BaseTool"):
    _CrewAIBaseTool = sys.modules["crewai.tools"].BaseTool
elif "crewai" in sys.modules and hasattr(sys.modules["crewai"], "BaseTool"):
    _CrewAIBaseTool = sys.modules["crewai"].BaseTool
else:
    try:
        from crewai.tools import BaseTool as _ImportedBaseTool
        _CrewAIBaseTool = _ImportedBaseTool
    except ImportError:
        try:
            from crewai_tools import BaseTool as _ImportedBaseTool
            _CrewAIBaseTool = _ImportedBaseTool
        except ImportError:
            _CrewAIBaseTool = None

if _CrewAIBaseTool is None:
    raise ImportError(
        "The AgentShield CrewAI integration requires 'crewai'. "
        "Install it with: pip install 'agentshield[crewai]'"
    )

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


def _clean_call_arguments(args: Any) -> Any:
    if isinstance(args, dict):
        return {
            k: v for k, v in args.items()
            if not k.startswith("_") and k not in ("idempotency_key",)
        }
    return args


def _get_target_callable(tool: Any) -> Tuple[Callable, Optional[Callable]]:
    """Returns (entrypoint_callable, underlying_implementation_callable)."""
    if hasattr(tool, "run") and callable(tool.run):
        impl = getattr(tool, "_run", None) if callable(getattr(tool, "_run", None)) else None
        return tool.run, impl
    if hasattr(tool, "_run") and callable(tool._run):
        return tool._run, tool._run
    if callable(tool):
        return tool, tool
    raise TypeError(f"Wrapped tool {tool} is neither callable nor implements run/_run")


def _dispatch_call(entrypoint: Callable, impl: Optional[Callable], exec_args: Any) -> Any:
    if not isinstance(exec_args, dict):
        return entrypoint(exec_args)
    clean_kwargs = _clean_call_arguments(exec_args)
    check_func = impl or entrypoint
    try:
        sig = inspect.signature(check_func)
        params = list(sig.parameters.values())
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        if has_var_kw:
            return entrypoint(**clean_kwargs)
        param_names = {p.name for p in params}
        matching = {k: v for k, v in clean_kwargs.items() if k in param_names}
        if matching or not clean_kwargs:
            return entrypoint(**matching)
        if len(params) == 1:
            return entrypoint(clean_kwargs)
        return entrypoint(**clean_kwargs)
    except (ValueError, TypeError):
        try:
            return entrypoint(**clean_kwargs)
        except TypeError:
            return entrypoint(clean_kwargs)


def _get_atarget_callable(tool: Any) -> Tuple[Optional[Callable], Optional[Callable]]:
    """Returns (async_entrypoint, async_impl) or (None, None)."""
    if hasattr(tool, "arun") and callable(tool.arun):
        impl = getattr(tool, "_arun", None) if callable(getattr(tool, "_arun", None)) else None
        return tool.arun, impl
    if hasattr(tool, "_arun") and callable(tool._arun):
        return tool._arun, tool._arun
    if callable(tool) and asyncio.iscoroutinefunction(tool):
        return tool, tool
    return None, None


async def _adispatch_call(entrypoint: Callable, impl: Optional[Callable], exec_args: Any) -> Any:
    if not isinstance(exec_args, dict):
        return await entrypoint(exec_args)
    clean_kwargs = _clean_call_arguments(exec_args)
    check_func = impl or entrypoint
    try:
        sig = inspect.signature(check_func)
        params = list(sig.parameters.values())
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        if has_var_kw:
            return await entrypoint(**clean_kwargs)
        param_names = {p.name for p in params}
        matching = {k: v for k, v in clean_kwargs.items() if k in param_names}
        if matching or not clean_kwargs:
            return await entrypoint(**matching)
        if len(params) == 1:
            return await entrypoint(clean_kwargs)
        return await entrypoint(**clean_kwargs)
    except (ValueError, TypeError):
        try:
            return await entrypoint(**clean_kwargs)
        except TypeError:
            return await entrypoint(clean_kwargs)


class AgentShieldCrewAITool(_CrewAIBaseTool):
    """CrewAI tool wrapper enforcing AgentShield runtime security policy,
    parameter validation, risk evaluation, and audit logging.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    args_schema: Optional[Type[BaseModel]] = Field(default=None, description="Tool argument schema")
    result_as_answer: bool = Field(default=False, description="Whether tool result is the final answer")

    wrapped_tool: Any = Field(..., description="Underlying CrewAI tool or callable")
    shield: Any = Field(..., description="AgentShield runtime instance")
    agent: Optional[str] = Field(default=None, description="Default agent identity")
    permissions: Optional[List[str]] = Field(default=None, description="Required permissions")
    correlation_id: Optional[str] = Field(default=None, description="Default correlation ID")
    raise_on_blocked: bool = Field(default=True, description="Whether to raise on blocked decisions")
    read_only: bool = Field(default=False, description="Whether tool is read-only")
    idempotent: bool = Field(default=False, description="Whether tool is idempotent")
    call_count: int = Field(default=0, description="Invocation counter for testing and auditing")

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
    ) -> AgentShieldCrewAITool:
        """Wrap an existing CrewAI tool or callable with AgentShield protections."""
        return protect_crewai_tool(
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
                param_names = []
                if self.args_schema and hasattr(self.args_schema, "model_fields"):
                    param_names = list(self.args_schema.model_fields.keys())
                for i, val in enumerate(args):
                    p_name = param_names[i] if i < len(param_names) else f"arg_{i}"
                    if p_name not in arguments:
                        arguments[p_name] = val
        elif args:
            if len(args) == 1 and isinstance(args[0], dict):
                arguments = dict(args[0])
            elif len(args) == 1:
                param_names = []
                if self.args_schema and hasattr(self.args_schema, "model_fields"):
                    param_names = list(self.args_schema.model_fields.keys())
                if len(param_names) == 1:
                    arguments = {param_names[0]: args[0]}
                else:
                    arguments = {"input": args[0]}
            else:
                param_names = []
                if self.args_schema and hasattr(self.args_schema, "model_fields"):
                    param_names = list(self.args_schema.model_fields.keys())
                arguments = {}
                for i, val in enumerate(args):
                    p_name = param_names[i] if i < len(param_names) else f"arg_{i}"
                    arguments[p_name] = val
        else:
            arguments = {}

        if isinstance(arguments, dict):
            if "_agent" in arguments:
                effective_agent = arguments.pop("_agent")
            if "_permissions" in arguments:
                effective_permissions = arguments.pop("_permissions")
            if "_correlation_id" in arguments:
                effective_correlation_id = arguments.pop("_correlation_id")

        return effective_agent, effective_permissions, effective_correlation_id, arguments

    def _execute_underlying_tool(self, exec_args: Any) -> Any:
        entry, impl = _get_target_callable(self.wrapped_tool)
        return _dispatch_call(entry, impl, exec_args)

    async def _aexecute_underlying_tool(self, exec_args: Any) -> Any:
        a_entry, a_impl = _get_atarget_callable(self.wrapped_tool)
        if a_entry is not None:
            return await _adispatch_call(a_entry, a_impl, exec_args)
        entry, impl = _get_target_callable(self.wrapped_tool)
        return await asyncio.to_thread(_dispatch_call, entry, impl, exec_args)

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
            evidence=["Tool executed successfully via CrewAI adapter"],
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
            evidence=[f"CrewAI tool execution error: {err_msg}"],
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
            res = self._execute_underlying_tool(exec_args)
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

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

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
            res = await self._aexecute_underlying_tool(exec_args)
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

    async def arun(self, *args: Any, **kwargs: Any) -> Any:
        return await self._arun(*args, **kwargs)


def protect_crewai_tool(
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
) -> AgentShieldCrewAITool:
    """Wraps a CrewAI BaseTool (or callable) with AgentShield security policy enforcement.

    Parameters:
        tool: A CrewAI BaseTool, or callable.
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
    tool_name = name or getattr(tool, "name", None) or getattr(tool, "__name__", "unnamed_crewai_tool")
    tool_desc = description or getattr(tool, "description", None) or getattr(tool, "__doc__", "") or ""
    tool_args_schema = getattr(tool, "args_schema", None)
    tool_result_as_answer = getattr(tool, "result_as_answer", False)
    tool_meta = dict(getattr(tool, "metadata", None) or {})
    if metadata:
        tool_meta.update(metadata)

    wrapped = AgentShieldCrewAITool(
        name=tool_name,
        description=tool_desc,
        args_schema=tool_args_schema,
        result_as_answer=tool_result_as_answer,
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
        entry, impl = _get_target_callable(tool)
        return _dispatch_call(entry, impl, exec_args)

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
    "AgentShieldCrewAITool",
    "protect_crewai_tool",
]
