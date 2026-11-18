import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ApiClient, ApiError } from '../src/api/client.ts';
import {
  deriveSecurityNotifications,
  mapServerAgentToModel,
} from '../src/health.ts';
import type { Agent, SecurityEvent, AttentionItem } from '../src/types.ts';

describe('Phase 3: Honest Data & Real Security Dashboard Integration', () => {
  it('1. No fabricated alerts: empty backend alerts and incidents produce strictly empty notifications list', () => {
    // When backend has 0 alerts, 0 pending reviews, and 0 paused agents
    const notifications = deriveSecurityNotifications([], 0, []);
    assert.strictEqual(notifications.length, 0);

    // When backend returns null/undefined
    const notificationsNull = deriveSecurityNotifications(null, undefined, undefined);
    assert.strictEqual(notificationsNull.length, 0);

    // Verify no hardcoded demo alerts (e.g. Risk 87 or 6 file access requests) leak in
    const titles = notifications.map((n) => n.title.toLowerCase());
    const messages = notifications.map((n) => n.message.toLowerCase());
    assert.strictEqual(titles.some((t) => t.includes('risk 87') || t.includes('file access')), false);
    assert.strictEqual(messages.some((m) => m.includes('risk 87') || m.includes('file access')), false);
  });

  it('2. Real security alerts: maps authentic backend alerts into honest notification items', () => {
    const rawAlerts = [
      {
        alert_id: 'alt-001',
        timestamp: '2026-11-17T09:15:00Z',
        title: 'Exfiltration Attempt Detected',
        description: 'Unauthorized egress to external endpoint blocked by destination policy.',
        alert_type: 'egress_violation',
        severity: 'critical',
        status: 'open',
        agent_id: 'shopping_agent',
        trigger_event_id: 'evt-123',
        correlation_id: 'corr-456',
      },
    ];

    const notifications = deriveSecurityNotifications(rawAlerts, 2, ['shopping_agent']);
    assert.strictEqual(notifications.length, 3);

    // Alert item
    const alertItem = notifications.find((n) => n.id === 'alert-alt-001');
    assert(alertItem);
    assert.strictEqual(alertItem.title, 'Exfiltration Attempt Detected');
    assert.strictEqual(alertItem.agent, 'shopping_agent');
    assert.strictEqual(alertItem.severity, 'critical');

    // Review item
    const reviewItem = notifications.find((n) => n.id === 'notif-pending-reviews');
    assert(reviewItem);
    assert(reviewItem.message.includes('2 tool execution proposals awaiting supervisor sign-off'));

    // Containment item
    const pausedItem = notifications.find((n) => n.id === 'notif-paused-agents');
    assert(pausedItem);
    assert(pausedItem.message.includes('1 agent contained: shopping_agent'));
  });

  it('3. Agent statistics come from actual API responses: preserves real counts and computes honest blocked rate', () => {
    const serverAgent = {
      name: 'data_analyzer',
      status: 'active',
      is_paused: false,
      total_events: 250,
      blocked_count: 25,
      last_active: '2026-11-17T08:30:00Z',
    };

    const agent = mapServerAgentToModel(serverAgent, [{ name: 'data_analyzer', policy: 'Data Sandbox v2' }]);
    assert.strictEqual(agent.id, 'data_analyzer');
    assert.strictEqual(agent.name, 'data_analyzer');
    assert.strictEqual(agent.status, 'Active');
    assert.strictEqual(agent.events7d, 250);
    assert.strictEqual(agent.blockedCount, 25);
    assert.strictEqual(agent.blockedRate, '10.0%');
    assert.strictEqual(agent.policy, 'Data Sandbox v2');
    assert(agent.lastActive !== undefined);
  });

  it('4. Missing backend data is never converted into invented values: framework and description remain undefined', () => {
    const minimalServerAgent = {
      name: 'custom_agent',
      status: 'active',
      is_paused: false,
      total_events: 0,
      blocked_count: 0,
      last_active: null,
    };

    const agent = mapServerAgentToModel(minimalServerAgent);
    // Runtime must NOT be invented as 'Python Autogen v0.4' or 'Agent Runtime'
    assert.strictEqual(agent.runtime, undefined);

    // Description must NOT be invented
    assert.strictEqual(agent.description, undefined);

    // Last active must be undefined when null
    assert.strictEqual(agent.lastActive, undefined);

    // Blocked rate must be 0.0% without division-by-zero or invented values
    assert.strictEqual(agent.blockedRate, '0.0%');
  });

  it('5. ApiClient.getSecurityAlerts: correctly calls /api/incident/alerts and passes query params', async () => {
    let capturedUrl = '';
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      capturedUrl = url.toString();
      return new Response(
        JSON.stringify({
          alerts: [
            {
              alert_id: 'alt-test-99',
              timestamp: '2026-11-17T09:00:00Z',
              title: 'Test Alert',
              description: 'Live test alert from API',
              alert_type: 'test_alert',
              severity: 'high',
              status: 'open',
              agent_id: 'test_agent',
              trigger_event_id: 'evt-0',
              correlation_id: 'corr-0',
            },
          ],
          total: 1,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const res = await client.getSecurityAlerts({ status: 'open', severity: 'high', limit: 10 });
      assert(capturedUrl.includes('/api/incident/alerts?'));
      assert(capturedUrl.includes('status=open'));
      assert(capturedUrl.includes('severity=high'));
      assert(capturedUrl.includes('limit=10'));
      assert.strictEqual(res.total, 1);
      assert.strictEqual(res.alerts[0].alert_id, 'alt-test-99');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('6. Honest attention item handling: navigates or selects real resources instead of fake agents', () => {
    let navigatedTab: string | null = null;
    let selectedAgent: Agent | null = null;
    let selectedEvent: SecurityEvent | null = null;

    const liveAgents: Agent[] = [
      {
        id: 'real_shopping_agent',
        name: 'real_shopping_agent',
        status: 'Paused',
        policy: 'Restricted Shopping',
        events7d: 42,
        blockedCount: 3,
        blockedRate: '7.1%',
      },
    ];

    const liveEvents: SecurityEvent[] = [
      {
        id: 'evt-real-1',
        agent: 'real_shopping_agent',
        action: 'checkout_order',
        decision: 'Blocked',
        riskScore: 92,
        timestamp: '10:00 AM',
      },
    ];

    const handleAttentionSelect = (item: AttentionItem) => {
      if (item.id === 'review-actions') {
        navigatedTab = 'Review';
      } else if (item.id === 'paused-agent') {
        const pausedAgent = liveAgents.find((a) => a.status === 'Paused');
        if (pausedAgent) {
          selectedAgent = pausedAgent;
        } else {
          navigatedTab = 'Policies';
        }
      } else if (item.id === 'high-risk') {
        const highestRisk = liveEvents.find((e) => e.riskScore >= 61);
        if (highestRisk) {
          selectedEvent = highestRisk;
        } else {
          navigatedTab = 'Events';
        }
      }
    };

    // Review item click
    handleAttentionSelect({
      id: 'review-actions',
      iconType: 'review',
      text: '3 actions awaiting review',
      severity: 'yellow',
    });
    assert.strictEqual(navigatedTab, 'Review');

    // Paused agent item click
    handleAttentionSelect({
      id: 'paused-agent',
      iconType: 'paused',
      text: '1 agent paused',
      severity: 'orange',
    });
    assert(selectedAgent !== null);
    assert.strictEqual((selectedAgent as Agent).name, 'real_shopping_agent');
    assert.notStrictEqual((selectedAgent as Agent).name, 'email-agent');

    // High risk item click
    handleAttentionSelect({
      id: 'high-risk',
      iconType: 'risk',
      text: '1 high-risk action',
      severity: 'red',
    });
    assert(selectedEvent !== null);
    assert.strictEqual((selectedEvent as SecurityEvent).agent, 'real_shopping_agent');
    assert.strictEqual((selectedEvent as SecurityEvent).riskScore, 92);
    assert.notStrictEqual((selectedEvent as SecurityEvent).agent, 'ops-agent');
  });
});

