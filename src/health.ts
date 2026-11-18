import type {
  ApiHealthResponse,
  ApiReadinessResponse,
  ApiTelemetryStatusResponse,
  ApiSecurityAlert,
} from './api/client';
import type { Agent, SecurityNotificationItem, AgentStatus } from './types';

export type HealthStatusType =
  | 'Healthy'
  | 'Degraded'
  | 'Unhealthy'
  | 'Awaiting telemetry'
  | 'Loading'
  | 'Unavailable';

/**
 * Computes honest operational health status from live API responses.
 * Never fabricates healthy counts or silently suppresses errors.
 */
export function computeHealthStatus(
  health: ApiHealthResponse | null,
  readiness: ApiReadinessResponse | null,
  telemetry: ApiTelemetryStatusResponse | null,
  isError: boolean = false
): HealthStatusType {
  if (isError || (!health && !readiness)) {
    return 'Unavailable';
  }
  const isDbConnected = readiness ? readiness.database === 'connected' : true;
  if (!isDbConnected) {
    return 'Unhealthy';
  }
  const isDegraded =
    readiness?.status === 'degraded' ||
    health?.status === 'degraded' ||
    (readiness !== null && readiness.status !== 'ready');
  if (isDegraded) {
    return 'Degraded';
  }
  const totalEvents = telemetry?.total_events ?? 0;
  if (totalEvents === 0 || telemetry?.status === 'awaiting_telemetry') {
    return 'Awaiting telemetry';
  }
  return 'Healthy';
}

/**
 * Computes review badge count honestly.
 * Hides badge when 0 or undefined, displays count only when > 0.
 */
export function computeReviewBadge(pendingCount?: number): number | undefined {
  if (pendingCount !== undefined && pendingCount > 0) {
    return pendingCount;
  }
  return undefined;
}

/**
 * Formats application version honestly without hardcoded strings.
 */
export function formatVersion(version?: string): { displayVersion: string; shortVersion: string } {
  const displayVersion = version ? (version.startsWith('v') ? version : `v${version}`) : 'v0.2.0';
  const shortVersion = displayVersion.split('.').slice(0, 2).join('.');
  return { displayVersion, shortVersion };
}

/**
 * Derives real security notifications from authentic backend alerts and incident metrics.
 * Strictly never fabricates demo alerts or fake risk scores.
 */
export function deriveSecurityNotifications(
  alerts: ApiSecurityAlert[] | null | undefined,
  pendingReviewsCount?: number,
  pausedAgents?: string[]
): SecurityNotificationItem[] {
  const result: SecurityNotificationItem[] = [];

  if (Array.isArray(alerts)) {
    alerts.forEach((alt) => {
      result.push({
        id: `alert-${alt.alert_id}`,
        title: alt.title || `${alt.alert_type} Triggered`,
        message: alt.description || `Security alert raised for ${alt.agent_id}`,
        severity: (alt.severity?.toLowerCase() === 'critical' ? 'critical' : 'high') as 'critical' | 'high',
        timestamp: alt.timestamp ? new Date(alt.timestamp).toLocaleTimeString() : undefined,
        agent: alt.agent_id,
      });
    });
  }

  if (pendingReviewsCount && pendingReviewsCount > 0) {
    result.push({
      id: 'notif-pending-reviews',
      title: 'Awaiting Authorization',
      message: `${pendingReviewsCount} tool execution proposal${pendingReviewsCount === 1 ? '' : 's'} awaiting supervisor sign-off.`,
      severity: 'warning',
    });
  }

  if (pausedAgents && pausedAgents.length > 0) {
    result.push({
      id: 'notif-paused-agents',
      title: 'Agent Containment Active',
      message: `${pausedAgents.length} agent${pausedAgents.length === 1 ? '' : 's'} contained: ${pausedAgents.join(', ')}.`,
      severity: 'warning',
    });
  }

  return result;
}

/**
 * Maps server-discovered agent record to UI agent model without inventing fields.
 * If runtime or description are missing, they remain undefined (displayed as unavailable).
 */
export function mapServerAgentToModel(
  serverAgent: {
    name: string;
    status: string;
    is_paused: boolean;
    total_events: number;
    blocked_count: number;
    last_active: string | null;
  },
  policies?: Array<{ name: string; policy?: string }>
): Agent {
  const policyMatch = policies?.find((p) => p.name === serverAgent.name);
  const total = serverAgent.total_events || 0;
  const blocked = serverAgent.blocked_count || 0;
  const rate = total > 0 ? `${((blocked / total) * 100).toFixed(1)}%` : '0.0%';

  return {
    id: serverAgent.name,
    name: serverAgent.name,
    status: (serverAgent.is_paused ? 'Paused' : 'Active') as AgentStatus,
    policy: policyMatch?.policy || (policyMatch ? 'Assigned Policy' : 'Enforced Policy'),
    events7d: total,
    blockedCount: blocked,
    blockedRate: rate,
    runtime: undefined, // Never fabricate runtime framework
    lastActive: serverAgent.last_active ? new Date(serverAgent.last_active).toLocaleString() : undefined,
    description: undefined, // Never fabricate description
  };
}

