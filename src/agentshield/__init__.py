"""AgentShield core package."""

__version__ = "0.1.0"

from .shield import (
    Shield,
    ExecutionResult,
    ExecutionStatus,
    ToolBlockedError,
    ToolReviewRequiredError,
)
from .models import (
    Decision,
    DecisionValue,
    RiskLevel,
)
from .policy import (
    PolicyEngine,
    PolicyConfiguration,
    AgentConfig,
    ToolRule,
    PolicyValidationError,
)
from .risk import RiskEngine
from .detector import PromptInjectionDetector, InjectionFinding
from .audit import AuditStore, SQLiteAuditStore, AuditRecord
from .review import ReviewStore, SQLiteReviewStore, ReviewExecutionState, FencingError
from .secrets import SecretProvider, DictSecretProvider, EnvSecretProvider
from .events import (
    SecurityEvent,
    SecurityAlert,
    SecurityIncident,
    EventType,
    EventSeverity,
    AlertStatus,
    IncidentStatus,
    EventStore,
    SQLiteEventStore,
    SecurityEventManager,
    AlertRule,
    AlertRuleEngine,
)
from .analyst import (
    AnalysisReport,
    AnalystSeverity,
    AnalysisValidationError,
    ProviderError,
    ReadOnlyViolationError,
    TimelineEntry,
    FindingObservation,
    SuspiciousSequence,
    LLMProvider,
    MockLLMProvider,
    SecurityAnalyst,
    ReportStore,
    SQLiteReportStore,
)
from .reliability import (
    ReliabilityConfig,
    parse_rate_limit,
    ExecutionLimitError,
    OperationCancelledError,
    ToolExecutionTimeoutError,
    ToolCallBudgetExceededError,
    PayloadSizeLimitError,
    TokenBudgetExceededError,
    SessionBudgetTracker,
    TokenBudgetTracker,
    CancellationToken,
    SafeExecutionContext,
    check_arguments_size,
    execute_with_timeout,
    LoopCheckResult,
    LoopDetector,
    compute_call_fingerprint,
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    BaseRateLimiter,
    InMemoryRateLimiter,
    SqliteRateLimiter,
    PostgresRateLimiter,
    RateLimitResult,
    create_rate_limiter,
)
from .config_validation import validate_runtime_config, sanitize_url, ConfigValidationResult

__all__ = [
    "__version__",
    "Shield",
    "Decision",
    "DecisionValue",
    "RiskLevel",
    "ExecutionResult",
    "ExecutionStatus",
    "ToolBlockedError",
    "ToolReviewRequiredError",
    "PolicyEngine",
    "PolicyConfiguration",
    "AgentConfig",
    "ToolRule",
    "PolicyValidationError",
    "RiskEngine",
    "PromptInjectionDetector",
    "InjectionFinding",
    "AuditStore",
    "SQLiteAuditStore",
    "AuditRecord",
    "ReviewStore",
    "SQLiteReviewStore",
    "ReviewExecutionState",
    "FencingError",
    "SecretProvider",
    "DictSecretProvider",
    "EnvSecretProvider",
    "SecurityEvent",
    "SecurityAlert",
    "SecurityIncident",
    "EventType",
    "EventSeverity",
    "AlertStatus",
    "IncidentStatus",
    "EventStore",
    "SQLiteEventStore",
    "SecurityEventManager",
    "AlertRule",
    "AlertRuleEngine",
    "AnalysisReport",
    "AnalystSeverity",
    "AnalysisValidationError",
    "ProviderError",
    "ReadOnlyViolationError",
    "TimelineEntry",
    "FindingObservation",
    "SuspiciousSequence",
    "LLMProvider",
    "MockLLMProvider",
    "GeminiProvider",
    "SecurityAnalyst",
    "ReportStore",
    "SQLiteReportStore",
    "ReliabilityConfig",
    "parse_rate_limit",
    "ExecutionLimitError",
    "OperationCancelledError",
    "ToolExecutionTimeoutError",
    "ToolCallBudgetExceededError",
    "PayloadSizeLimitError",
    "TokenBudgetExceededError",
    "SessionBudgetTracker",
    "TokenBudgetTracker",
    "CancellationToken",
    "SafeExecutionContext",
    "check_arguments_size",
    "execute_with_timeout",
    "LoopCheckResult",
    "LoopDetector",
    "compute_call_fingerprint",
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
    "BaseRateLimiter",
    "InMemoryRateLimiter",
    "SqliteRateLimiter",
    "PostgresRateLimiter",
    "RateLimitResult",
    "create_rate_limiter",
    "validate_runtime_config",
    "sanitize_url",
    "ConfigValidationResult",
    "AgentShieldTool",
    "protect_langchain_tool",
    "AgentShieldCrewAITool",
    "protect_crewai_tool",
]


def __getattr__(name: str):
    """Lazy import handler for optional integrations and providers."""
    if name in ("AgentShieldTool", "protect_langchain_tool"):
        from .integrations.langchain import AgentShieldTool, protect_langchain_tool
        return locals()[name]
    if name in ("AgentShieldCrewAITool", "protect_crewai_tool"):
        from .integrations.crewai import AgentShieldCrewAITool, protect_crewai_tool
        return locals()[name]
    if name == "GeminiProvider":
        from .analyst.providers.gemini import GeminiProvider
        return GeminiProvider
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
