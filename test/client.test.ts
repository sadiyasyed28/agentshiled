import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert';
import { ApiClient, ApiError } from '../src/api/client.ts';

describe('Root Pixel-Art ApiClient Test Suite', () => {
  it('constructs with base URL and normalizes trailing slashes', () => {
    const client = new ApiClient('http://localhost:8000/');
    assert.strictEqual(client['baseUrl'], 'http://localhost:8000');
  });

  it('handles successful GET requests for health and overview', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/health')) {
        return new Response(JSON.stringify({ status: 'ok', version: '0.1.0', engine: 'deterministic' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (urlStr.endsWith('/api/overview')) {
        return new Response(JSON.stringify({
          total_evaluated: 150,
          allow_count: 100,
          review_count: 20,
          block_count: 30,
          pending_reviews_count: 2,
          paused_agents: [],
          active_incidents_count: 0,
          is_read_only: false,
          is_live: true,
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const health = await client.getHealth();
      assert.strictEqual(health.status, 'ok');

      const overview = await client.getOverview();
      assert.strictEqual(overview.total_evaluated, 150);
      assert.strictEqual(overview.allow_count, 100);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('includes CSRF token for mutating requests', async () => {
    let capturedHeaders: Headers | null = null;
    let capturedBody: string | null = null;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/session')) {
        return new Response(JSON.stringify({
          authenticated: true,
          csrf_token: 'csrf-token-xyz-123',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (urlStr.endsWith('/api/incident/pause')) {
        capturedHeaders = new Headers(init?.headers);
        capturedBody = init?.body as string;
        return new Response(JSON.stringify({ agent: 'research-agent', status: 'paused' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      await client.getSession();

      const pauseRes = await client.pauseAgent('research-agent');
      assert.strictEqual(pauseRes.status, 'paused');
      assert.strictEqual(capturedHeaders?.get('x-csrf-token'), 'csrf-token-xyz-123');
      assert.deepStrictEqual(JSON.parse(capturedBody!), { agent: 'research-agent' });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('submits review actions with exact request schema', async () => {
    let capturedBody: string | null = null;
    let capturedMethod: string | null = null;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      if (url.toString().endsWith('/api/incident/review')) {
        capturedMethod = init?.method || null;
        capturedBody = init?.body as string;
        return new Response(JSON.stringify({ status: 'approved', execution_status: 'executed' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const res = await client.submitReview('rev-123', 'approve');
      assert.strictEqual(res.status, 'approved');
      assert.strictEqual(capturedMethod, 'POST');
      const parsed = JSON.parse(capturedBody!);
      assert.strictEqual(parsed.review_id, 'rev-123');
      assert.strictEqual(parsed.action, 'approve');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('propagates HTTP error status and detail properly', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      return new Response(JSON.stringify({ detail: 'Forbidden: Untrusted request origin' }), {
        status: 403,
        statusText: 'Forbidden',
        headers: { 'Content-Type': 'application/json' },
      });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      await assert.rejects(
        async () => {
          await client.getPolicies();
        },
        (err: ApiError) => {
          assert.strictEqual(err.status, 403);
          assert.ok(err.message.includes('Untrusted request origin'));
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

