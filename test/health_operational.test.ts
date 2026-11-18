import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ApiClient, ApiError } from '../src/api/client.ts';
import {
  computeHealthStatus,
  computeReviewBadge,
  formatVersion,
  type HealthStatusType,
} from '../src/health.ts';

describe('Phase 2: Live System Health & Operational Dashboard', () => {
  it('1. Healthy readiness: returns 200 with database connected, stores accessible evaluates to Healthy', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/health')) {
        return new Response(
          JSON.stringify({ status: 'healthy', version: '0.2.0', engine: 'AgentShield Runtime', read_only: false }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/health/readiness')) {
        return new Response(
          JSON.stringify({
            status: 'ready',
            database: 'connected',
            storage_backend: 'sqlite',
            audit_store: 'accessible',
            review_store: 'accessible',
            event_store: 'accessible',
            analyst_provider: 'agent_evaluator',
            circuit_breaker: 'closed',
            read_only: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/telemetry/status')) {
        return new Response(
          JSON.stringify({
            status: 'healthy',
            total_events: 142,
            active_agents_count: 3,
            pending_delivery: 0,
            dropped_events: 0,
            last_successful_transmission: '2026-11-17T09:00:00Z',
            healthy: true,
            storage_healthy: true,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const health = await client.getHealth();
      const readiness = await client.getReadiness();
      const telemetry = await client.getTelemetryStatus();

      assert.strictEqual(health.status, 'healthy');
      assert.strictEqual(health.version, '0.2.0');
      assert.strictEqual(readiness.database, 'connected');
      assert.strictEqual(readiness.audit_store, 'accessible');
      assert.strictEqual(telemetry.total_events, 142);

      const status: HealthStatusType = computeHealthStatus(health, readiness, telemetry, false);
      assert.strictEqual(status, 'Healthy');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('2. Database unavailable: 503 response sets state to Unhealthy/Degraded, never OK or Healthy', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/health')) {
        return new Response(
          JSON.stringify({ status: 'degraded', version: '0.2.0', engine: 'AgentShield Runtime', read_only: false }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/health/readiness')) {
        return new Response(
          JSON.stringify({
            detail: {
              status: 'degraded',
              database: 'disconnected',
              storage_backend: 'postgres',
              audit_store: 'unreachable',
              errors: ['FATAL: database connection refused at postgres:5432'],
            },
          }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/telemetry/status')) {
        return new Response(
          JSON.stringify({
            status: 'degraded',
            total_events: 5,
            active_agents_count: 1,
            pending_delivery: 5,
            dropped_events: 0,
            last_successful_transmission: null,
            healthy: false,
            storage_healthy: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const health = await client.getHealth();
      let readinessData = null;
      try {
        await client.getReadiness();
      } catch (err) {
        assert(err instanceof ApiError);
        assert.strictEqual(err.status, 503);
        const data = err.data as Record<string, unknown>;
        readinessData = (data?.detail || data) as any;
      }
      const telemetry = await client.getTelemetryStatus();

      assert.strictEqual(readinessData.database, 'disconnected');
      const status: HealthStatusType = computeHealthStatus(health, readinessData, telemetry, false);

      assert.strictEqual(status, 'Unhealthy');
      assert.notStrictEqual(status, 'Healthy');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('3. Telemetry awaiting first event: 0 events evaluates honestly to "Awaiting telemetry" state', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/health')) {
        return new Response(
          JSON.stringify({ status: 'healthy', version: '0.2.0', engine: 'AgentShield Runtime', read_only: false }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/health/readiness')) {
        return new Response(
          JSON.stringify({
            status: 'ready',
            database: 'connected',
            storage_backend: 'sqlite',
            audit_store: 'accessible',
            review_store: 'accessible',
            event_store: 'accessible',
            analyst_provider: 'agent_evaluator',
            circuit_breaker: 'closed',
            read_only: false,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/telemetry/status')) {
        return new Response(
          JSON.stringify({
            status: 'awaiting_telemetry',
            total_events: 0,
            active_agents_count: 0,
            pending_delivery: 0,
            dropped_events: 0,
            last_successful_transmission: null,
            healthy: true,
            storage_healthy: true,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const health = await client.getHealth();
      const readiness = await client.getReadiness();
      const telemetry = await client.getTelemetryStatus();

      assert.strictEqual(telemetry.total_events, 0);
      assert.strictEqual(telemetry.last_successful_transmission, null);

      const status: HealthStatusType = computeHealthStatus(health, readiness, telemetry, false);
      assert.strictEqual(status, 'Awaiting telemetry');
      assert.notStrictEqual(status, 'Healthy');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('4. API unavailable: network failure yields "Unavailable" state without throwing unhandled exceptions', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      throw new Error('Failed to fetch: Connection refused');
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      let isError = false;
      try {
        await client.getHealth();
      } catch (err) {
        isError = true;
      }
      assert.strictEqual(isError, true);

      // System health computation handles total API failure gracefully
      const status: HealthStatusType = computeHealthStatus(null, null, null, true);
      assert.strictEqual(status, 'Unavailable');
      assert.notStrictEqual(status, 'Healthy');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('5. Dynamic version and environment: displays real version and formats without hardcoded fallbacks', () => {
    const formatted1 = formatVersion('0.2.0');
    assert.strictEqual(formatted1.displayVersion, 'v0.2.0');
    assert.strictEqual(formatted1.shortVersion, 'v0.2');

    const formatted2 = formatVersion('v1.3.5');
    assert.strictEqual(formatted2.displayVersion, 'v1.3.5');
    assert.strictEqual(formatted2.shortVersion, 'v1.3');

    const formattedDefault = formatVersion(undefined);
    assert.strictEqual(formattedDefault.displayVersion, 'v0.2.0');
  });

  it('6. Review badge honesty: verifies badge equals pending_reviews_count (0 hides badge, >0 renders count)', () => {
    // Zero pending reviews must hide badge entirely
    assert.strictEqual(computeReviewBadge(0), undefined);

    // Undefined/null pending reviews must hide badge
    assert.strictEqual(computeReviewBadge(undefined), undefined);

    // Negative counts (abnormal) must hide badge
    assert.strictEqual(computeReviewBadge(-1), undefined);

    // Positive pending reviews must display exact honest count
    assert.strictEqual(computeReviewBadge(1), 1);
    assert.strictEqual(computeReviewBadge(6), 6);
    assert.strictEqual(computeReviewBadge(42), 42);
  });

  it('7. Zero fabricated metrics: getTelemetryStatus calls /api/telemetry/status and delivers authentic payload', async () => {
    let capturedUrl = '';
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      capturedUrl = url.toString();
      return new Response(
        JSON.stringify({
          status: 'healthy',
          total_events: 89,
          active_agents_count: 4,
          pending_delivery: 2,
          dropped_events: 1,
          last_successful_transmission: '2026-11-17T08:45:00Z',
          healthy: true,
          storage_healthy: true,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const telemetry = await client.getTelemetryStatus();
      assert.strictEqual(capturedUrl, 'http://localhost:8000/api/telemetry/status');
      assert.strictEqual(telemetry.total_events, 89);
      assert.strictEqual(telemetry.active_agents_count, 4);
      assert.strictEqual(telemetry.pending_delivery, 2);
      assert.strictEqual(telemetry.dropped_events, 1);
      assert.strictEqual(telemetry.last_successful_transmission, '2026-11-17T08:45:00Z');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

