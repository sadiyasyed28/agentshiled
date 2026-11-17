export interface ApiDecisionResponse {
  allowed: boolean;
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  reasons: string[];
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  agent: string;
  tool: string;
}

export interface ApiExecutionResponse {
  decision: ApiDecisionResponse;
  execution_status: "executed" | "not_executed" | "error";
  tool_result?: unknown;
  error?: string | null;
}

export interface ApiEventItem {
  id: number;
  timestamp: string;
  agent: string;
  tool: string;
  arguments: Record<string, unknown>;
  decision: "ALLOW" | "REVIEW" | "BLOCK";
  allowed: boolean;
  reasons: string[];
  rules_triggered: string[];
  risk_score: number;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  execution_status: "executed" | "not_executed" | "error";
  error?: string | null;
  correlation_id?: string | null;
  trace_id?: string | null;
}

export interface ApiReadinessResponse {
  status: string;
  database: string;
  storage_backend: string;
  audit_store: string;
  review_store: string;
  event_store: string;
  analyst_provider: string;
  circuit_breaker: string;
  read_only?: boolean;
}

export interface ApiIncidentTraceResponse {
  incident: ApiSecurityIncident;
  alerts: ApiSecurityAlert[];
  events: Array<Record<string, unknown>>;
  audit_records: ApiEventItem[];
  summary: Record<string, unknown>;
}

export interface ApiEventsResponse {
  events: ApiEventItem[];
  total: number;
}

export interface ApiHealthResponse {
  status: string;
  version: string;
  engine: string;
  read_only?: boolean;
}

export interface ApiOverviewStats {
  allow: number;
  review: number;
  block: number;
  total: number;
  paused_agents: number;
}

export interface ApiPolicyRuleItem {
  name: string;
  target: string;
  description: string;
  status: "active" | "enforcing";
}

export interface ApiPoliciesResponse {
  version_hash: string;
  known_tools: string[];
  agents: Array<{
    name: string;
    allowed_tools: string[];
    denied_tools: string[];
    allowed_destinations: string[];
  }>;
  tools: Array<{
    tool: string;
    max_quantity?: number | null;
    max_amount?: number | null;
    required_permissions: string[];
    allowed_destinations: string[];
  }>;
  policies: ApiPolicyRuleItem[];
}

export interface ApiRiskFactorItem {
  id: string;
  name: string;
  weight: number;
  description: string;
}

export interface ApiRiskFactorsResponse {
  factors: ApiRiskFactorItem[];
  severity_thresholds: {
    low_max: number;
    medium_max: number;
    high_max: number;
  };
}

export interface ApiRuntimeConfigResponse {
  environment: string;
  read_only: boolean;
  storage_backend: string;
  database_configured: boolean;
  analyst_provider: string;
  analyst_model?: string | null;
  mock_fallback_enabled: boolean;
  max_tool_execution_seconds: number;
  max_tool_calls_per_session: number;
  max_arguments_bytes: number;
  max_body_bytes: number;
  max_token_budget: number;
  rate_limit_agent: string;
  rate_limit_tool: string;
  rate_limit_public: string;
  rate_limit_analyst: string;
  loop_consecutive_limit: number;
  loop_cycle_limit: number;
  circuit_breaker_failure_threshold: number;
  circuit_breaker_recovery_timeout: number;
  policy_version_hash: string;
  admin_auth_configured: boolean;
}

export interface ApiSessionResponse {
  authenticated: boolean;
  expires_at: number | null;
  csrf_token?: string | null;
  tenant_id?: string;
  role?: string;
}

export interface ApiKeyItem {
  key_id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  last_four: string;
  masked_key: string;
  created_at: number;
  revoked_at?: number | null;
  last_used_at?: number | null;
  is_active: boolean;
}

export interface ApiRegisterResponse {
  status: string;
  tenant_id: string;
  name: string;
  email: string;
  api_key: string;
  key_id: string;
  masked_key: string;
  csrf_token?: string | null;
  created_at: number;
}

export interface ApiCreatedKeyResponse {
  status: string;
  key_id: string;
  tenant_id: string;
  name: string;
  masked_key: string;
  api_key: string;
  created_at: number;
}

export interface ApiTenantInfo {
  tenant_id: string;
  name: string;
  owner_email: string;
  created_at: number;
}

export interface ApiDiscoveredAgent {
  name: string;
  status: "active" | "paused";
  is_paused: boolean;
  total_events: number;
  blocked_count: number;
  last_active: string | null;
}

export interface ApiAgentsResponse {
  agents: ApiDiscoveredAgent[];
  paused_agents: string[];
  total: number;
  tenant_id?: string;
}

export interface ApiTelemetryStatusResponse {
  status: "connected" | "awaiting_telemetry";
  tenant_id: string;
  total_events: number;
  active_agents_count: number;
  last_event_timestamp: string | null;
  last_successful_transmission: string | null;
  pending_delivery: number;
  dropped_events: number;
  healthy: boolean;
}

export interface ApiAuditVerifyResponse {
  valid: boolean;
  message: string;
  checked_count: number;
  genesis_hash: string | null;
}

export interface ApiPendingReview {
  review_id: string;
  agent: string;
  tool: string;
  arguments: Record<string, unknown>;
  risk_score: number;
  reasons: string[];
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
  created_at: string;
}

export interface ApiReviewsResponse {
  pending: ApiPendingReview[];
  count: number;
}

export interface ApiSecurityAlert {
  alert_id: string;
  incident_id?: string | null;
  rule_name: string;
  agent: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  message: string;
  timestamp: string;
}

export interface ApiSecurityIncident {
  incident_id: string;
  agent: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED";
  trigger_reason: string;
  alerts_count: number;
  created_at: string;
  updated_at: string;
}

export interface ApiInvestigationReport {
  incident_id: string;
  summary: string;
  attack_vector: string;
  severity_assessment: string;
  recommended_actions: string[];
  generated_at: string;
  model: string;
  fallback?: boolean;
}

export interface ApiSimulationScenario {
  id: string;
  name: string;
  description: string;
  attack_category: string;
  simulation_type: string;
  agent: string;
  tool: string;
  arguments: Record<string, unknown>;
  input_payload: string;
  permissions: string[];
  expected_decision: string;
  expected_severity: string;
  explanation: string;
}

export interface ApiSimulationRun {
  run_id: string;
  scenario_id: string;
  scenario_name: string;
  attack_category: string;
  timestamp: number;
  actual_decision?: "ALLOW" | "REVIEW" | "BLOCK" | "ERROR" | "FAILED" | string | null;
  expected_decision: string;
  expectation_matched: boolean;
  risk_score?: number | null;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | string | null;
  latency_ms: number;
  reasons: string[];
  rules_triggered: string[];
  execution_status: string;
  tool_result?: unknown;
  error_category?: string | null;
  error?: string | null;
}

export interface ApiSimulatorSummary {
  total_runs: number;
  allow_count: number;
  review_count: number;
  block_count: number;
  failed_runs?: number;
  expectation_matches: number;
  expectation_match_rate: number;
  avg_latency_ms: number;
  recent_runs: ApiSimulationRun[];
}

const API_BASE_URL = (typeof import.meta !== "undefined" && import.meta.env?.VITE_API_URL) || (typeof window !== "undefined" ? window.location.origin : "http://localhost:8000");

export class ApiClient {
  private baseUrl: string;
  private csrfToken: string | null = null;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  private getCookie(name: string): string | null {
    if (typeof document === "undefined") return null;
    const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const headers = new Headers(options.headers || {});
    if (!headers.has("Content-Type") && options.body && typeof options.body === "string") {
      headers.set("Content-Type", "application/json");
    }

    const method = (options.method || "GET").toUpperCase();
    if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
      const csrf = this.csrfToken || this.getCookie("agentshield_csrf");
      if (csrf) {
        headers.set("x-csrf-token", csrf);
      }
    }

    const response = await fetch(url, {
      ...options,
      headers,
      credentials: "include",
    });

    if (!response.ok) {
      let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData?.detail) {
          errorMsg = typeof errorData.detail === "string" ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch {
        // fallback to status code error
      }
      const err = new Error(errorMsg);
      (err as unknown as { status: number }).status = response.status;
      throw err;
    }

    return response.json();
  }

  async getHealth(): Promise<ApiHealthResponse> {
    return this.request<ApiHealthResponse>("/health");
  }

  async getOverview(): Promise<ApiOverviewStats> {
    return this.request<ApiOverviewStats>("/api/overview");
  }

  async getEvents(limit: number = 50): Promise<ApiEventsResponse> {
    return this.request<ApiEventsResponse>(`/events?limit=${limit}`);
  }

  async getSession(): Promise<ApiSessionResponse> {
    const res = await this.request<{
      authenticated: boolean;
      expires_at?: number | null;
      csrf_token?: string | null;
      tenant_id?: string;
      role?: string;
    }>("/api/auth/session");
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    return {
      authenticated: res.authenticated,
      expires_at: res.expires_at ?? null,
      csrf_token: res.csrf_token ?? null,
      tenant_id: res.tenant_id,
      role: res.role,
    };
  }

  async login(adminKey?: string, email?: string, password?: string): Promise<ApiSessionResponse> {
    const body: Record<string, string> = {};
    if (adminKey) body.admin_key = adminKey;
    if (email) body.email = email;
    if (password) body.password = password;

    const res = await this.request<{
      authenticated: boolean;
      expires_at?: number | null;
      csrf_token?: string | null;
      tenant_id?: string;
      role?: string;
    }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(body),
    });
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    return {
      authenticated: res.authenticated,
      expires_at: res.expires_at ?? null,
      csrf_token: res.csrf_token ?? null,
      tenant_id: res.tenant_id,
      role: res.role,
    };
  }

  async register(
    name: string,
    email: string,
    password: string,
    tenantId?: string
  ): Promise<ApiRegisterResponse> {
    const res = await this.request<ApiRegisterResponse>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        name,
        email,
        password,
        tenant_id: tenantId || null,
      }),
    });
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    return res;
  }

  async getApiKeys(tenantId?: string): Promise<{ keys: ApiKeyItem[]; total: number }> {
    const q = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
    return this.request<{ keys: ApiKeyItem[]; total: number }>(`/api/api-keys${q}`);
  }

  async createApiKey(name: string = "Default Key", prefix: string = "ash_live"): Promise<ApiCreatedKeyResponse> {
    return this.request<ApiCreatedKeyResponse>("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({ name, prefix }),
    });
  }

  async revokeApiKey(keyId: string): Promise<{ status: string; key_id: string }> {
    return this.request<{ status: string; key_id: string }>(`/api/api-keys/${encodeURIComponent(keyId)}/revoke`, {
      method: "POST",
    });
  }

  async rotateApiKey(keyId: string, name?: string): Promise<ApiCreatedKeyResponse> {
    return this.request<ApiCreatedKeyResponse>(`/api/api-keys/${encodeURIComponent(keyId)}/rotate`, {
      method: "POST",
      body: JSON.stringify({ name: name || null }),
    });
  }

  async getTenantMe(): Promise<ApiTenantInfo> {
    return this.request<ApiTenantInfo>("/api/tenant/me");
  }

  async logout(): Promise<ApiSessionResponse> {
    const res = await this.request<ApiSessionResponse>("/api/auth/logout", {
      method: "POST",
    });
    this.csrfToken = null;
    return res;
  }

  async verifyAudit(): Promise<ApiAuditVerifyResponse> {
    return this.request<ApiAuditVerifyResponse>("/api/audit/verify");
  }

  async getReviews(): Promise<ApiReviewsResponse> {
    const res = await this.request<{ reviews?: ApiPendingReview[]; pending?: ApiPendingReview[]; count?: number }>("/incident/reviews");
    const list = res.reviews || res.pending || [];
    return {
      pending: list,
      count: res.count ?? list.length,
    };
  }

  async submitReview(
    reviewId: string,
    decision: "APPROVE" | "REJECT",
    rationale: string = "Reviewed from web console",
    reviewer: string = "admin"
  ): Promise<{ status: string; review_id: string; decision: string }> {
    return this.request<{ status: string; review_id: string; decision: string }>("/incident/review", {
      method: "POST",
      body: JSON.stringify({
        review_id: reviewId,
        action: decision.toLowerCase(),
        decision,
        reason: rationale,
        reviewer,
      }),
    });
  }

  async getIncidents(): Promise<{ incidents: ApiSecurityIncident[]; count: number }> {
    return this.request<{ incidents: ApiSecurityIncident[]; count: number }>("/incident/incidents");
  }

  async getAlerts(): Promise<{ alerts: ApiSecurityAlert[]; count: number }> {
    return this.request<{ alerts: ApiSecurityAlert[]; count: number }>("/incident/alerts");
  }

  async getReport(incidentId: string): Promise<ApiInvestigationReport> {
    const res = await this.request<{ report?: Record<string, unknown> }>(`/incident/report/${encodeURIComponent(incidentId)}`);
    const rep = (res.report || res) as Record<string, unknown>;
    return {
      incident_id: String(rep.incident_id || incidentId),
      summary: String(rep.summary || rep.incident_summary || "No investigation summary available"),
      attack_vector: String(rep.attack_vector || rep.threat_vector || "Unknown attack vector"),
      severity_assessment: String(rep.severity_assessment || "MEDIUM"),
      recommended_actions: Array.isArray(rep.recommended_actions) ? (rep.recommended_actions as string[]) : [],
      generated_at: String(rep.generated_at || rep.created_at || new Date().toISOString()),
      model: String(rep.model || rep.analyst_model || "gemini-2.5-flash"),
    };
  }

  async generateReport(incidentId: string, forceRefresh: boolean = false): Promise<ApiInvestigationReport> {
    const res = await this.request<{ report?: Record<string, unknown> }>("/incident/report", {
      method: "POST",
      body: JSON.stringify({ incident_id: incidentId, force_refresh: forceRefresh }),
    });
    const rep = (res.report || res) as Record<string, unknown>;
    return {
      incident_id: String(rep.incident_id || incidentId),
      summary: String(rep.summary || rep.incident_summary || "No investigation summary available"),
      attack_vector: String(rep.attack_vector || rep.threat_vector || "Unknown attack vector"),
      severity_assessment: String(rep.severity_assessment || "MEDIUM"),
      recommended_actions: Array.isArray(rep.recommended_actions) ? (rep.recommended_actions as string[]) : [],
      generated_at: String(rep.generated_at || rep.created_at || new Date().toISOString()),
      model: String(rep.model || rep.analyst_model || "gemini-2.5-flash"),
    };
  }

  async getPausedAgents(): Promise<{ paused_agents: string[] }> {
    return this.request<{ paused_agents: string[] }>("/incident/agents");
  }

  async getDiscoveredAgents(tenantId?: string): Promise<ApiAgentsResponse> {
    const query = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
    return this.request<ApiAgentsResponse>(`/api/agents${query}`);
  }

  async getTelemetryStatus(tenantId?: string): Promise<ApiTelemetryStatusResponse> {
    const query = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : "";
    return this.request<ApiTelemetryStatusResponse>(`/api/telemetry/status${query}`);
  }

  async pauseAgent(agent: string): Promise<{ paused: boolean; agent: string }> {
    return this.request<{ paused: boolean; agent: string }>("/incident/pause", {
      method: "POST",
      body: JSON.stringify({ agent }),
    });
  }

  async unpauseAgent(agent: string): Promise<{ paused: boolean; agent: string }> {
    return this.request<{ paused: boolean; agent: string }>("/incident/unpause", {
      method: "POST",
      body: JSON.stringify({ agent }),
    });
  }

  async authorize(
    agent: string,
    tool: string,
    args: Record<string, unknown> = {},
    permissions: string[] = []
  ): Promise<ApiDecisionResponse> {
    return this.request<ApiDecisionResponse>("/authorize", {
      method: "POST",
      body: JSON.stringify({ agent, tool, arguments: args, permissions }),
    });
  }

  async execute(
    agent: string,
    tool: string,
    args: Record<string, unknown> = {},
    permissions: string[] = []
  ): Promise<ApiExecutionResponse> {
    return this.request<ApiExecutionResponse>("/execute", {
      method: "POST",
      body: JSON.stringify({ agent, tool, arguments: args, permissions }),
    });
  }

  async getScenarios(): Promise<ApiSimulationScenario[]> {
    return this.request<ApiSimulationScenario[]>("/api/simulator/scenarios");
  }

  async getScenario(id: string): Promise<ApiSimulationScenario> {
    return this.request<ApiSimulationScenario>(`/api/simulator/scenarios/${encodeURIComponent(id)}`);
  }

  async runScenario(id: string): Promise<ApiSimulationRun> {
    return this.request<ApiSimulationRun>(`/api/simulator/run/${encodeURIComponent(id)}`, {
      method: "POST",
    });
  }

  async runBatch(scenarioIds?: string[]): Promise<ApiSimulationRun[]> {
    return this.request<ApiSimulationRun[]>("/api/simulator/run-batch", {
      method: "POST",
      body: JSON.stringify({ scenario_ids: scenarioIds || null }),
    });
  }

  async getSimulationHistory(limit: number = 50): Promise<ApiSimulationRun[]> {
    return this.request<ApiSimulationRun[]>(`/api/simulator/history?limit=${limit}`);
  }

  async getSimulatorSummary(): Promise<ApiSimulatorSummary> {
    return this.request<ApiSimulatorSummary>("/api/simulator/summary");
  }

  async clearSimulationHistory(): Promise<{ status: string; records_cleared: number }> {
    return this.request<{ status: string; records_cleared: number }>("/api/simulator/history", {
      method: "DELETE",
    });
  }

  async getReadiness(): Promise<ApiReadinessResponse> {
    return this.request<ApiReadinessResponse>("/health/readiness");
  }

  async getMetrics(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("/metrics");
  }

  async getIncidentTrace(incidentId: string): Promise<ApiIncidentTraceResponse> {
    return this.request<ApiIncidentTraceResponse>(`/api/security/incidents/${encodeURIComponent(incidentId)}/trace`);
  }

  async getPolicies(): Promise<ApiPoliciesResponse> {
    return this.request<ApiPoliciesResponse>("/api/policies");
  }

  async getRiskFactors(): Promise<ApiRiskFactorsResponse> {
    return this.request<ApiRiskFactorsResponse>("/api/risk/factors");
  }

  async getRuntimeConfig(): Promise<ApiRuntimeConfigResponse> {
    return this.request<ApiRuntimeConfigResponse>("/api/config");
  }
}

export const api = new ApiClient();
