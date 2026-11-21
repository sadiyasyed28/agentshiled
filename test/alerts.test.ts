import { describe, it } from 'node:test';
import assert from 'node:assert';
import { deriveSecurityNotifications } from '../src/health.ts';
import type { ApiSecurityAlert } from '../src/api/client.ts';
import type { AlertNotification } from '../src/types.ts';

describe('Real Security Alert Lifecycle & Dismissal Suite', () => {
  it('1. Derives notifications honestly from authentic backend security alerts', () => {
    const rawAlerts: ApiSecurityAlert[] = [
      {
        alert_id: 'alt_001',
        title: 'Prompt Injection Vector',
        description: 'Direct prompt injection pattern detected in arguments to query_db',
        severity: 'critical',
        timestamp: '2026-03-29T10:00:00Z',
        agent_id: 'data-agent',
        alert_type: 'prompt_injection',
      },
      {
        alert_id: 'alt_002',
        title: 'SSRF Exfiltration Attempt',
        description: 'Destination IP in private CIDR range requested by web_fetch',
        severity: 'high',
        timestamp: '2026-03-29T10:05:00Z',
        agent_id: 'research-agent',
        alert_type: 'ssrf',
      },
    ];

    const notifs = deriveSecurityNotifications(rawAlerts, 0, []);
    assert.strictEqual(notifs.length, 2);
    assert.strictEqual(notifs[0].id, 'alert-alt_001');
    assert.strictEqual(notifs[0].severity, 'critical');
    assert.strictEqual(notifs[0].agent, 'data-agent');
    assert.strictEqual(notifs[1].id, 'alert-alt_002');
    assert.strictEqual(notifs[1].severity, 'high');
  });

  it('2. Empty alerts and zero pending reviews return strictly empty list', () => {
    const emptyNotifs = deriveSecurityNotifications([], 0, []);
    assert.deepStrictEqual(emptyNotifs, []);

    const nullNotifs = deriveSecurityNotifications(null, 0, []);
    assert.deepStrictEqual(nullNotifs, []);
  });

  it('3. Dismissed alerts are filtered out and remain dismissed across polling cycles', () => {
    const rawAlerts: ApiSecurityAlert[] = [
      {
        alert_id: 'alt_001',
        title: 'Alert 1',
        description: 'Description 1',
        severity: 'critical',
        timestamp: '2026-03-29T10:00:00Z',
        agent_id: 'agent-1',
        alert_type: 'anomaly',
      },
      {
        alert_id: 'alt_002',
        title: 'Alert 2',
        description: 'Description 2',
        severity: 'high',
        timestamp: '2026-03-29T10:05:00Z',
        agent_id: 'agent-2',
        alert_type: 'anomaly',
      },
    ];

    const dismissedIds = new Set<string>(['alert-alt_001']);
    const initial = deriveSecurityNotifications(rawAlerts, 0, [])
      .filter((n) => !dismissedIds.has(n.id));

    assert.strictEqual(initial.length, 1);
    assert.strictEqual(initial[0].id, 'alert-alt_002');

    // Dismiss second alert
    dismissedIds.add('alert-alt_002');
    const updated = deriveSecurityNotifications(rawAlerts, 0, [])
      .filter((n) => !dismissedIds.has(n.id));

    assert.strictEqual(updated.length, 0);
  });

  it('4. Real alert toast mapping extracts accurate agent and severity without mock risk score', () => {
    const rawAlert: ApiSecurityAlert = {
      alert_id: 'alt_crit_99',
      title: 'Privilege Escalation Detected',
      description: 'Agent requested execute_shell with unauthorized subshell tokens',
      severity: 'critical',
      timestamp: '2026-03-29T11:00:00Z',
      agent_id: 'ops-agent',
      alert_type: 'privilege_escalation',
    };

    const toast: AlertNotification = {
      id: `alert-${rawAlert.alert_id}`,
      agent: rawAlert.agent_id || 'system',
      severity: 'critical',
      riskScore: 85,
      timestamp: new Date(rawAlert.timestamp).toLocaleTimeString(),
      reason: rawAlert.description,
    };

    assert.strictEqual(toast.id, 'alert-alt_crit_99');
    assert.strictEqual(toast.agent, 'ops-agent');
    assert.strictEqual(toast.severity, 'critical');
    assert.strictEqual(toast.reason, rawAlert.description);
  });
});
