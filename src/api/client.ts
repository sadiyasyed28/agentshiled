/**
 * AgentShield Typed API Client for Root Pixel-Art Frontend
 * Provides strongly-typed network calls, relative API routing,
 * CSRF management, session cookies, timeout protection, and clean error handling.
 */

export interface ApiHealthResponse {
  status: string;
  version: string;
  engine: string;
  read_only?: boolean;
}

export interface ApiReadinessResponse {
  status: string;
  database: string;
  storage_backend: string;
  audit_store?: string;
  review_store?: string;
  event_store?: string;
  analyst_provider?: string;
  circuit_breaker?: string;
  read_only?: boolean;
  errors?: string[];
  message?: string;
}

export interface ApiTelemetryStatusResponse {
  status: string;
  tenant_id: string;
  total_events: number;
  active_agents_count: number;
  last_event_timestamp?: string | null;
  last_successful_transmission?: string | null;
  pending_delivery: number;
  dropped_events: number;
  backend_exporter_pending?: number;
  backend_exporter_dropped?: number;
  healthy?: boolean;
  storage_healthy?: boolean;
  storage_error?: string | null;
}

export interface ApiOverviewStats {
  total_evaluated: number;
  allow_count: number;
  review_count: number;
  block_count: number;
  pending_reviews_count: number;
  paused_agents: string[];
  active_incidents_count: number;
  is_read_only: boolean;
  is_live: boolean;
  allow?: number;
  review?: number;
  block?: number;
  total?: number;
  decision_distribution?: {
    ALLOW: number;
    REVIEW: number;
    BLOCK: number;
  };
}

export interface ApiEventItem {
  id: number;
  timestamp: string;
  agent: string;
  tool: string;
  arguments: Record<string, unknown>;
  decision: 'ALLOW' | 'REVIEW' | 'BLOCK' | string;
  allowed: boolean;
  reasons: string[];
  rules_triggered: string[];
  risk_score: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  execution_status: string;
  error?: string | null;
  policy_version_hash?: string | null;
  prev_hash?: string | null;
  record_hash?: string | null;
  correlation_id?: string | null;
  trace_id?: string | null;
}

export interface ApiEventsResponse {
  events: ApiEventItem[];
  total: number;
}

export interface ApiAuditVerifyResponse {
  valid: boolean;
  total_records: number;
  error?: string | null;
  corrupted_record_id?: number | null;
}

export interface ApiPendingReview {
  review_id: string;
  agent_id?: string;
  agent?: string;
  tool_name?: string;
  tool?: string;
  arguments?: Record<string, unknown>;
  risk_score?: number;
  status?: string;
  created_at?: string;
  reasons?: string[];
  simulated?: boolean;
}

export interface ApiReviewsResponse {
  reviews: ApiPendingReview[];
  count: number;
}

export interface ApiReviewActionResult {
  status: string;
  execution_status?: string;
  result?: unknown;
  decision?: string;
  simulated?: boolean;
}

export interface ApiPolicyRuleItem {
  name: string;
  target: string;
  description: string;
  status: string;
}

export interface ApiAgentPolicyDetail {
  name: string;
  allowed_tools: string[];
  denied_tools: string[];
  allowed_destinations: string[];
}

export interface ApiToolPolicyDetail {
  tool: string;
  max_quantity?: number | null;
  max_amount?: number | null;
  required_permissions: string[];
  allowed_destinations: string[];
}

export interface ApiPoliciesResponse {
  version_hash: string;
  known_tools: string[];
  agents: ApiAgentPolicyDetail[];
  tools: ApiToolPolicyDetail[];
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
  actual_decision?: string | null;
  expected_decision: string;
  expectation_matched: boolean;
  risk_score?: number | null;
  severity?: string | null;
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
  failed_runs: number;
  expectation_matches: number;
  expectation_match_rate: number;
  avg_latency_ms: number;
  recent_runs: Record<string, unknown>[];
}

export interface ApiSessionResponse {
  authenticated: boolean;
  read_only?: boolean;
  admin_configured?: boolean;
  expires_at?: number | null;
  csrf_token?: string | null;
  tenant_id?: string | null;
  role?: string | null;
  status?: string;
}

export interface ApiSecurityAlert {
  alert_id: string;
  timestamp: string;
  title: string;
  description: string;
  alert_type: string;
  severity: string;
  status: string;
  agent_id: string;
  trigger_event_id: string;
  correlation_id: string;
  incident_id?: string | null;
  acknowledged_at?: string | null;
  acknowledged_by?: string | null;
  resolved_at?: string | null;
  resolved_by?: string | null;
  resolution_note?: string | null;
}

export interface ApiSecurityAlertsResponse {
  alerts: ApiSecurityAlert[];
  total: number;
}

export interface ApiAuditVerifyResponse {
  valid: boolean;
  total_records: number;
  error?: string | null;
  corrupted_record_id?: number | null;
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

export interface ApiKeysListResponse {
  keys: ApiKeyItem[];
  total: number;
}

export interface ApiKeyCreatedResponse {
  status: string;
  key_id: string;
  tenant_id: string;
  name: string;
  masked_key: string;
  api_key: string;
  created_at: number;
}

export interface ApiRuntimeConfigResponse {
  environment: string;
  read_only: boolean;
  storage_backend: string;
  database_configured: boolean;
  analyst_provider: string;
  analyst_model?: string | null;
  mock_fallback_enabled: boolean;
  max_tool_execution_seconds?: number;
  max_tool_calls_per_session?: number;
  max_arguments_bytes?: number;
  max_body_bytes?: number;
  max_token_budget?: number;
  rate_limit_agent?: number;
  rate_limit_tool?: number;
  rate_limit_public?: number;
  rate_limit_analyst?: number;
  loop_consecutive_limit?: number;
  loop_cycle_limit?: number;
  circuit_breaker_failure_threshold?: number;
  circuit_breaker_recovery_timeout?: number;
  policy_version_hash?: string;
  admin_auth_configured?: boolean;
}

export interface ApiLoginCredentials {
  admin_key?: string;
  email?: string;
  password?: string;
  tenant_id?: string;
}

// Relative URL by default so both Vercel same-origin and Vite dev proxy route cleanly
const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || '';

export class ApiError extends Error {
  status: number;
  data?: unknown;
  isAuthError: boolean;
  isForbidden: boolean;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
    this.isAuthError = status === 401;
    this.isForbidden = status === 403;
  }
}

export class ApiClient {
  private baseUrl: string;
  private csrfToken: string | null = null;
  private authListeners: Array<(session: ApiSessionResponse | null) => void> = [];

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  onAuthChange(listener: (session: ApiSessionResponse | null) => void): () => void {
    this.authListeners.push(listener);
    return () => {
      this.authListeners = this.authListeners.filter((l) => l !== listener);
    };
  }

  private notifyAuthChange(session: ApiSessionResponse | null) {
    this.authListeners.forEach((listener) => {
      try {
        listener(session);
      } catch {
        // ignore listener errors
      }
    });
  }

  private getCookie(name: string): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
    const headers = new Headers(options.headers || {});

    if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
      headers.set('Content-Type', 'application/json');
    }

    const method = (options.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      const csrf = this.csrfToken || this.getCookie('agentshield_csrf');
      if (csrf) {
        headers.set('x-csrf-token', csrf);
      }
    }

    // Default 10s request timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    const signal = options.signal || controller.signal;

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal,
        credentials: 'include',
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorMsg = `HTTP ${response.status}: ${response.statusText}`;
        let parsedData: unknown = null;
        try {
          parsedData = await response.json();
          if (parsedData && typeof parsedData === 'object' && 'detail' in (parsedData as Record<string, unknown>)) {
            const detail = (parsedData as Record<string, unknown>).detail;
            errorMsg = typeof detail === 'string' ? detail : JSON.stringify(detail);
          }
        } catch {
          // ignore json parse error on non-json body
        }
        throw new ApiError(errorMsg, response.status, parsedData);
      }

      return await response.json();
    } catch (err: unknown) {
      clearTimeout(timeoutId);
      if (err instanceof ApiError) throw err;
      if (err instanceof Error && err.name === 'AbortError') {
        throw new ApiError('Request timed out after 10000ms', 408);
      }
      throw new ApiError((err as Error)?.message || 'Network request failed', 0);
    }
  }

  /* ---------------------- Health & System ---------------------- */

  async getHealth(): Promise<ApiHealthResponse> {
    return this.request<ApiHealthResponse>('/api/health');
  }

  async getReadiness(): Promise<ApiReadinessResponse> {
    return this.request<ApiReadinessResponse>('/api/health/readiness');
  }

  async getRuntimeConfig(): Promise<ApiRuntimeConfigResponse> {
    return this.request<ApiRuntimeConfigResponse>('/api/config');
  }

  async getTelemetryStatus(): Promise<ApiTelemetryStatusResponse> {
    return this.request<ApiTelemetryStatusResponse>('/api/telemetry/status');
  }

  /* ---------------------- Auth & Session ----------------------- */

  async getSession(): Promise<ApiSessionResponse> {
    const res = await this.request<ApiSessionResponse>('/api/auth/session');
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    this.notifyAuthChange(res);
    return res;
  }

  async login(credentials: string | ApiLoginCredentials): Promise<ApiSessionResponse> {
    const payload = typeof credentials === 'string' ? { admin_key: credentials } : credentials;
    const res = await this.request<ApiSessionResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    this.notifyAuthChange(res);
    return res;
  }

  async logout(): Promise<{ status: string }> {
    const res = await this.request<{ status: string }>('/api/auth/logout', {
      method: 'POST',
    });
    this.csrfToken = null;
    this.notifyAuthChange(null);
    return res;
  }

  /* --------------------- Overview & Stats ---------------------- */

  async getOverview(): Promise<ApiOverviewStats> {
    return this.request<ApiOverviewStats>('/api/overview');
  }

  /* -------------------------- Events --------------------------- */

  async getEvents(query?: {
    decision?: string;
    agent?: string;
    tool?: string;
    limit?: number;
  }): Promise<ApiEventsResponse> {
    const params = new URLSearchParams();
    if (query?.decision && query.decision !== 'All') params.set('decision', query.decision.toUpperCase());
    if (query?.agent && query.agent !== 'All') params.set('agent', query.agent);
    if (query?.tool && query.tool !== 'All') params.set('tool', query.tool);
    if (query?.limit) params.set('limit', String(query.limit));

    const qs = params.toString() ? `?${params.toString()}` : '';
    // Public audit endpoint
    return this.request<ApiEventsResponse>(`/events${qs}`);
  }

  async verifyAudit(): Promise<ApiAuditVerifyResponse> {
    return this.request<ApiAuditVerifyResponse>('/api/audit/verify');
  }

  /* -------------------------- Reviews -------------------------- */

  async getReviews(): Promise<ApiReviewsResponse> {
    const res = await this.request<{ reviews?: ApiPendingReview[]; count?: number }>('/api/reviews');
    return {
      reviews: res.reviews || [],
      count: res.count ?? (res.reviews?.length || 0),
    };
  }

  async submitReview(
    reviewId: string,
    action: 'approve' | 'reject' | 'deny',
    reason?: string
  ): Promise<ApiReviewActionResult> {
    const normalizedAction = action.toLowerCase() === 'deny' ? 'reject' : action.toLowerCase();
    return this.request<ApiReviewActionResult>('/api/incident/review', {
      method: 'POST',
      body: JSON.stringify({
        review_id: reviewId,
        action: normalizedAction,
        reason: reason || undefined,
      }),
    });
  }

  /* --------------------- Policies & Agents --------------------- */

  async getPolicies(): Promise<ApiPoliciesResponse> {
    return this.request<ApiPoliciesResponse>('/api/policies');
  }

  async getRiskFactors(): Promise<ApiRiskFactorsResponse> {
    return this.request<ApiRiskFactorsResponse>('/api/risk/factors');
  }

  async getAgents(): Promise<{ paused_agents: string[]; agents?: Array<{ name: string; status: string; is_paused: boolean; total_events: number; blocked_count: number; last_active: string | null }> }> {
    return this.request<{ paused_agents: string[]; agents?: Array<{ name: string; status: string; is_paused: boolean; total_events: number; blocked_count: number; last_active: string | null }> }>('/api/incident/agents');
  }

  async pauseAgent(agent: string): Promise<{ agent: string; status: string }> {
    return this.request<{ agent: string; status: string }>('/api/incident/pause', {
      method: 'POST',
      body: JSON.stringify({ agent }),
    });
  }

  async unpauseAgent(agent: string): Promise<{ agent: string; status: string }> {
    return this.request<{ agent: string; status: string }>('/api/incident/unpause', {
      method: 'POST',
      body: JSON.stringify({ agent }),
    });
  }

  /* ------------------- Security Alerts & Incidents ------------------- */

  async getSecurityAlerts(params?: {
    status?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApiSecurityAlertsResponse> {
    const q = new URLSearchParams();
    if (params?.status) q.set('status', params.status);
    if (params?.severity) q.set('severity', params.severity);
    if (params?.limit) q.set('limit', String(params.limit));
    if (params?.offset) q.set('offset', String(params.offset));
    const qs = q.toString();
    return this.request<ApiSecurityAlertsResponse>(
      `/api/incident/alerts${qs ? `?${qs}` : ''}`
    );
  }

  /* ------------------- Audit Integrity Verification ------------------- */

  async verifyAuditIntegrity(): Promise<ApiAuditVerifyResponse> {
    return this.request<ApiAuditVerifyResponse>('/api/audit/verify');
  }

  /* ---------------------- API Key Management ------------------------ */

  async getApiKeys(tenantId?: string): Promise<ApiKeysListResponse> {
    const qs = tenantId ? `?tenant_id=${encodeURIComponent(tenantId)}` : '';
    return this.request<ApiKeysListResponse>(`/api/api-keys${qs}`);
  }

  async createApiKey(req: { name: string; prefix?: string; tenant_id?: string }): Promise<ApiKeyCreatedResponse> {
    return this.request<ApiKeyCreatedResponse>('/api/api-keys', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async rotateApiKey(keyId: string, req?: { name?: string }): Promise<ApiKeyCreatedResponse> {
    return this.request<ApiKeyCreatedResponse>(`/api/api-keys/${encodeURIComponent(keyId)}/rotate`, {
      method: 'POST',
      body: JSON.stringify(req || {}),
    });
  }

  async revokeApiKey(keyId: string): Promise<{ status: string; key_id: string; tenant_id: string }> {
    return this.request<{ status: string; key_id: string; tenant_id: string }>(`/api/api-keys/${encodeURIComponent(keyId)}/revoke`, {
      method: 'POST',
    });
  }

  /* ------------------------ Benchmarks ------------------------- */

  async getScenarios(): Promise<ApiSimulationScenario[]> {
    return this.request<ApiSimulationScenario[]>('/api/simulator/scenarios');
  }

  async getScenario(id: string): Promise<ApiSimulationScenario> {
    return this.request<ApiSimulationScenario>(`/api/simulator/scenarios/${encodeURIComponent(id)}`);
  }

  async runScenario(id: string): Promise<ApiSimulationRun> {
    return this.request<ApiSimulationRun>(`/api/simulator/run/${encodeURIComponent(id)}`, {
      method: 'POST',
    });
  }

  async runBatch(scenarioIds?: string[]): Promise<ApiSimulationRun[]> {
    return this.request<ApiSimulationRun[]>('/api/simulator/run-batch', {
      method: 'POST',
      body: JSON.stringify({ scenario_ids: scenarioIds || null }),
    });
  }

  async getSimulatorSummary(): Promise<ApiSimulatorSummary> {
    return this.request<ApiSimulatorSummary>('/api/simulator/summary');
  }

  async getSimulationHistory(limit: number = 50): Promise<ApiSimulationRun[]> {
    return this.request<ApiSimulationRun[]>(`/api/simulator/history?limit=${limit}`);
  }

  async clearSimulationHistory(): Promise<{ status: string; records_cleared: number }> {
    return this.request<{ status: string; records_cleared: number }>('/api/simulator/history/clear', {
      method: 'POST',
    });
  }
}

export const apiClient = new ApiClient();

