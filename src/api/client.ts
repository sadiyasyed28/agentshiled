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
  audit_store: string;
  review_store: string;
  event_store: string;
  analyst_provider: string;
  circuit_breaker: string;
  read_only?: boolean;
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
}

export interface ApiRuntimeConfigResponse {
  environment: string;
  read_only: boolean;
  storage_backend: string;
  database_configured: boolean;
  analyst_provider: string;
  analyst_model?: string | null;
  mock_fallback_enabled: boolean;
  policy_version_hash: string;
  admin_auth_configured: boolean;
}

// Relative URL by default so both Vercel same-origin and Vite dev proxy route cleanly
const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || '';

export class ApiError extends Error {
  status: number;
  data?: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export class ApiClient {
  private baseUrl: string;
  private csrfToken: string | null = null;

  constructor(baseUrl: string = API_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
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

  /* ---------------------- Auth & Session ----------------------- */

  async getSession(): Promise<ApiSessionResponse> {
    const res = await this.request<ApiSessionResponse>('/api/auth/session');
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    return res;
  }

  async login(adminKey: string): Promise<ApiSessionResponse> {
    const res = await this.request<ApiSessionResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ admin_key: adminKey }),
    });
    if (res.csrf_token) {
      this.csrfToken = res.csrf_token;
    }
    return res;
  }

  async logout(): Promise<{ status: string }> {
    const res = await this.request<{ status: string }>('/api/auth/logout', {
      method: 'POST',
    });
    this.csrfToken = null;
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

  async getAgents(): Promise<{ paused_agents: string[] }> {
    return this.request<{ paused_agents: string[] }>('/api/incident/agents');
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

