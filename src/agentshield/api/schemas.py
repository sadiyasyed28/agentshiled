"""
Typed Pydantic request and response models for AgentShield FastAPI server.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str
    version: str
    engine: str
    read_only: bool = False

class CheckRequest(BaseModel):
    text: str = Field(..., max_length=10000, description="User input text to inspect")

class AuthorizeRequest(BaseModel):
    agent: str = Field(..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    tool: str = Field(..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    arguments: Dict[str, Any] = Field(default_factory=dict)
    permissions: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = Field(None, max_length=128)

class ExecuteRequest(BaseModel):
    agent: str = Field(..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    tool: str = Field(..., min_length=1, max_length=256, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    arguments: Dict[str, Any] = Field(default_factory=dict)
    permissions: List[str] = Field(default_factory=list)
    tenant_id: Optional[str] = Field(None, max_length=128)

class DecisionResponse(BaseModel):
    allowed: bool
    decision: str
    reasons: List[str]
    risk_score: float
    severity: str
    agent: str
    tool: str
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None

class ExecutionResponse(BaseModel):
    decision: DecisionResponse
    execution_status: str
    tool_result: Optional[Any] = None
    error: Optional[str] = None
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None

class PauseAgentRequest(BaseModel):
    agent: str = Field(..., max_length=256)
    tenant_id: Optional[str] = Field(None, max_length=128)

class ReviewActionRequest(BaseModel):
    review_id: str
    action: str = Field("approve", description="'approve' or 'reject'")
    reason: Optional[str] = None
    tenant_id: Optional[str] = Field(None, max_length=128)

class EventItem(BaseModel):
    id: int
    timestamp: str
    agent: str
    tool: str
    arguments: Dict[str, Any]
    decision: str
    allowed: bool
    reasons: List[str]
    rules_triggered: List[str]
    risk_score: float
    severity: str
    execution_status: str
    error: Optional[str] = None
    policy_version_hash: Optional[str] = None
    prev_hash: Optional[str] = None
    record_hash: Optional[str] = None
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None
    tenant_id: Optional[str] = "default"

class EventsResponse(BaseModel):
    events: List[EventItem]
    total: int

class AuditVerifyResponse(BaseModel):
    valid: bool
    total_records: int
    error: Optional[str] = None
    corrupted_record_id: Optional[int] = None

class SecurityEventModel(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    tool: str
    event_type: str
    severity: str
    decision: Optional[str] = None
    risk_score: float
    evidence: List[str] = Field(default_factory=list)
    trace_id: str
    correlation_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = "default"

class SecurityEventsResponse(BaseModel):
    events: List[SecurityEventModel]
    total: int

class SecurityAlertModel(BaseModel):
    alert_id: str
    timestamp: str
    title: str
    description: str
    alert_type: str
    severity: str
    status: str
    agent_id: str
    trigger_event_id: str
    event_ids: List[str] = Field(default_factory=list)
    correlation_id: str
    incident_id: Optional[str] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_note: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = "default"

class SecurityAlertsResponse(BaseModel):
    alerts: List[SecurityAlertModel]
    total: int

class SecurityIncidentModel(BaseModel):
    incident_id: str
    created_at: str
    updated_at: str
    title: str
    description: str
    severity: str
    status: str
    correlation_id: str
    agent_id: str
    alert_ids: List[str] = Field(default_factory=list)
    event_count: int
    assigned_to: Optional[str] = None
    resolution_summary: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = "default"

class SecurityIncidentsResponse(BaseModel):
    incidents: List[SecurityIncidentModel]
    total: int

class AnalysisRequest(BaseModel):
    incident_id: Optional[str] = Field(None, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    correlation_id: Optional[str] = Field(None, max_length=128, pattern=r"^[a-zA-Z0-9_\-\.:]+$")
    force_refresh: Optional[bool] = False
    tenant_id: Optional[str] = Field(None, max_length=128)

class AnalysisResponse(BaseModel):
    report: Dict[str, Any]

class AnalysisReportsListResponse(BaseModel):
    reports: List[Dict[str, Any]]
    total: int

class AuthLoginRequest(BaseModel):
    admin_key: str = Field(..., max_length=1024, description="Administrative authentication key")
    tenant_id: Optional[str] = Field(None, max_length=128, description="Target tenant ID (optional)")

class AuthSessionResponse(BaseModel):
    authenticated: bool
    read_only: bool = False
    admin_configured: bool = False
    expires_at: Optional[float] = None
    csrf_token: Optional[str] = None
    tenant_id: Optional[str] = "default"
    role: Optional[str] = "tenant_admin"

class OverviewStatsResponse(BaseModel):
    total_evaluated: int
    allow_count: int
    review_count: int
    block_count: int
    pending_reviews_count: int
    paused_agents: List[str]
    active_incidents_count: int
    is_read_only: bool
    is_live: bool
    allow: int = 0
    review: int = 0
    block: int = 0
    total: int = 0
    tenant_id: Optional[str] = "default"
    simulated: bool = False

class ScenarioModel(BaseModel):
    id: str
    name: str
    description: str
    attack_category: str
    simulation_type: str
    agent: str
    tool: str
    arguments: Dict[str, Any]
    input_payload: str
    permissions: List[str]
    expected_decision: str
    expected_severity: str
    explanation: str

class SimulationRunModel(BaseModel):
    run_id: str
    scenario_id: str
    scenario_name: str
    attack_category: str
    timestamp: float
    actual_decision: Optional[str] = None
    expected_decision: str
    expectation_matched: bool
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    latency_ms: float
    reasons: List[str] = Field(default_factory=list)
    rules_triggered: List[str] = Field(default_factory=list)
    execution_status: str = "COMPLETED"
    tool_result: Optional[Any] = None
    error_category: Optional[str] = None
    error: Optional[str] = None

class SimulatorSummaryModel(BaseModel):
    total_runs: int
    allow_count: int
    review_count: int
    block_count: int
    failed_runs: int = 0
    expectation_matches: int
    expectation_match_rate: float
    avg_latency_ms: float
    recent_runs: List[Dict[str, Any]] = Field(default_factory=list)

class BatchRunRequest(BaseModel):
    scenario_ids: Optional[List[str]] = Field(None, max_length=20, description="List of scenario IDs to run (max 20)")

class ReadinessResponse(BaseModel):
    status: str
    database: str
    storage_backend: str
    audit_store: str
    review_store: str
    event_store: str
    analyst_provider: str
    circuit_breaker: str
    read_only: bool = False

class IncidentTraceResponse(BaseModel):
    incident: SecurityIncidentModel
    alerts: List[SecurityAlertModel]
    events: List[SecurityEventModel]
    audit_records: List[EventItem]
    summary: Dict[str, Any]

class PolicyRuleItem(BaseModel):
    name: str
    target: str
    description: str
    status: str = "enforcing"

class AgentPolicyDetail(BaseModel):
    name: str
    allowed_tools: List[str] = Field(default_factory=list)
    denied_tools: List[str] = Field(default_factory=list)
    allowed_destinations: List[str] = Field(default_factory=list)

class ToolPolicyDetail(BaseModel):
    tool: str
    max_quantity: Optional[float] = None
    max_amount: Optional[float] = None
    required_permissions: List[str] = Field(default_factory=list)
    allowed_destinations: List[str] = Field(default_factory=list)

class PoliciesResponse(BaseModel):
    version_hash: str
    known_tools: List[str]
    agents: List[AgentPolicyDetail]
    tools: List[ToolPolicyDetail]
    policies: List[PolicyRuleItem]

class RiskFactorItem(BaseModel):
    id: str
    name: str
    weight: float
    description: str

class SeverityThresholds(BaseModel):
    low_max: float
    medium_max: float
    high_max: float

class RiskFactorsResponse(BaseModel):
    factors: List[RiskFactorItem]
    severity_thresholds: SeverityThresholds

class RuntimeConfigResponse(BaseModel):
    environment: str
    read_only: bool
    storage_backend: str
    database_configured: bool
    analyst_provider: str
    analyst_model: Optional[str] = None
    mock_fallback_enabled: bool
    max_tool_execution_seconds: float
    max_tool_calls_per_session: int
    max_arguments_bytes: int
    max_body_bytes: int
    max_token_budget: int
    rate_limit_agent: str
    rate_limit_tool: str
    rate_limit_public: str
    rate_limit_analyst: str
    loop_consecutive_limit: int
    loop_cycle_limit: int
    circuit_breaker_failure_threshold: int
    circuit_breaker_recovery_timeout: float
    policy_version_hash: str
    admin_auth_configured: bool
