export type AgentStatus = 'Active' | 'Paused' | 'Blocked';

export interface Agent {
  id: string;
  name: string;
  status: AgentStatus;
  policy: string;
  events7d: number;
  blockedCount: number;
  blockedRate: string;
  description?: string;
  runtime?: string;
  lastActive?: string;
}

export type DecisionType = 'Allowed' | 'Review' | 'Blocked';

export interface SecurityEvent {
  id: string;
  agent: string;
  action: string;
  decision: DecisionType;
  riskScore: number;
  timestamp: string;
  payloadSummary?: string;
  reason?: string;
}

export interface AttentionItem {
  id: string;
  iconType: 'review' | 'paused' | 'risk' | 'policy';
  text: string;
  count?: number;
  severity: 'yellow' | 'orange' | 'red' | 'purple';
  details?: string;
}

export interface RiskTier {
  name: string;
  range: string;
  percentage: number;
  count: number;
  color: string;
}

export interface AlertNotification {
  id: string;
  agent: string;
  reason: string;
  riskScore: number;
  severity: 'critical' | 'warning' | 'info' | 'success';
  timestamp: string;
}

export interface SecurityNotificationItem {
  id: string;
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'warning' | 'info';
  timestamp?: string;
  agent?: string;
  riskScore?: number;
  onAction?: () => void;
}

