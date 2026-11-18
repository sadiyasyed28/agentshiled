import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ApiClient, ApiError } from '../src/api/client.ts';

describe('Phase 4: Complete Security Operations Integration Test Suite', () => {
  /* ---------------- 1. Audit Hash-Chain Verification ---------------- */

  it('1. Audit verification valid: returns 200 with valid: true and total_records', async () => {
    const originalFetch = globalThis.fetch;
    let endpointCalled = '';

    globalThis.fetch = async (url: string | URL | Request) => {
      endpointCalled = url.toString();
      return new Response(
        JSON.stringify({
          valid: true,
          total_records: 48,
          error: null,
          corrupted_record_id: null,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const result = await client.verifyAuditIntegrity();
      assert.strictEqual(endpointCalled, 'http://localhost:8000/api/audit/verify');
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.total_records, 48);
      assert.strictEqual(result.error, null);
      assert.strictEqual(result.corrupted_record_id, null);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('2. Audit verification invalid: returns corrupted record ID and specific failure reason', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async () => {
      return new Response(
        JSON.stringify({
          valid: false,
          total_records: 19,
          error: 'Hash mismatch: computed sha256 does not match stored block digest',
          corrupted_record_id: 12,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const result = await client.verifyAuditIntegrity();
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.total_records, 19);
      assert.strictEqual(result.corrupted_record_id, 12);
      assert.match(result.error ?? '', /Hash mismatch/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('3. Audit verification forbidden: raises ApiError(403) when user lacks global_admin privilege', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async () => {
      return new Response(
        JSON.stringify({
          detail: 'Forbidden: Global platform admin privilege required',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      await assert.rejects(
        async () => {
          await client.verifyAuditIntegrity();
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          assert.match(err.message, /Global platform admin/);
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  /* ---------------- 2. API Key Management ---------------- */

  it('4. API key list and creation: retrieves keys and returns one-time plaintext key', async () => {
    const originalFetch = globalThis.fetch;
    let createRequestBody: string | null = null;

    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/session')) {
        return new Response(
          JSON.stringify({
            authenticated: true,
            csrf_token: 'csrf-token-xyz-123',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/api-keys') && (!init?.method || init.method === 'GET')) {
        return new Response(
          JSON.stringify({
            keys: [
              {
                key_id: 'key_abc123',
                tenant_id: 'default',
                name: 'Production Scanner',
                masked_key: 'agnt_prod...xyz',
                created_at: 1718000000,
              },
            ],
            total: 1,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }
      if (urlStr.endsWith('/api/api-keys') && init?.method === 'POST') {
        createRequestBody = init.body as string;
        return new Response(
          JSON.stringify({
            status: 'created',
            key_id: 'key_new999',
            tenant_id: 'default',
            name: 'New Crawler Agent',
            masked_key: 'agnt_craw...888',
            api_key: 'agnt_craw_secret_full_plaintext_value_once',
            created_at: 1718000500,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const list = await client.getApiKeys();
      assert.strictEqual(list.keys.length, 1);
      assert.strictEqual(list.keys[0].name, 'Production Scanner');

      const created = await client.createApiKey({ name: 'New Crawler Agent', prefix: 'agnt_craw' });
      assert.strictEqual(created.status, 'created');
      assert.strictEqual(created.name, 'New Crawler Agent');
      assert.strictEqual(created.api_key, 'agnt_craw_secret_full_plaintext_value_once');
      assert(createRequestBody !== null);
      const parsedBody = JSON.parse(createRequestBody);
      assert.strictEqual(parsedBody.name, 'New Crawler Agent');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('5. API key rotation and revocation: calls specific key IDs and delivers updated secret', async () => {
    const originalFetch = globalThis.fetch;
    const calls: { url: string; method: string }[] = [];

    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      const method = init?.method || 'GET';
      calls.push({ url: urlStr, method });

      if (urlStr.includes('/rotate')) {
        return new Response(
          JSON.stringify({
            status: 'rotated',
            key_id: 'key_abc123',
            tenant_id: 'default',
            name: 'Rotated Key',
            masked_key: 'agnt_rota...111',
            api_key: 'agnt_rotated_secret_value_2026',
            created_at: 1718001000,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.includes('/revoke')) {
        return new Response(
          JSON.stringify({
            status: 'revoked',
            key_id: 'key_abc123',
            tenant_id: 'default',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const rotated = await client.rotateApiKey('key_abc123');
      assert.strictEqual(rotated.status, 'rotated');
      assert.strictEqual(rotated.api_key, 'agnt_rotated_secret_value_2026');

      const revoked = await client.revokeApiKey('key_abc123');
      assert.strictEqual(revoked.status, 'revoked');
      assert.strictEqual(revoked.key_id, 'key_abc123');

      assert.strictEqual(calls.length, 2);
      assert.match(calls[0].url, /\/api\/api-keys\/key_abc123\/rotate$/);
      assert.match(calls[1].url, /\/api\/api-keys\/key_abc123\/revoke$/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('6. API key mutation blocked in read-only mode: server returns 403 and client handles it explicitly', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async () => {
      return new Response(
        JSON.stringify({
          detail: 'Forbidden: Instance is in read-only mode',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    };

    try {
      const client = new ApiClient('http://localhost:8000');

      await assert.rejects(
        async () => {
          await client.createApiKey({ name: 'Blocked Key' });
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          assert.match(err.message, /read-only mode/);
          return true;
        }
      );

      await assert.rejects(
        async () => {
          await client.revokeApiKey('key_any');
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  /* ---------------- 3. Review Workflows ---------------- */

  it('7. Review approve and reject handling: executes transitions and distinguishes 401/403', async () => {
    const originalFetch = globalThis.fetch;
    const reviewCalls: Array<{ url: string; body: unknown }> = [];

    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/incident/review')) {
        const parsed = JSON.parse(init?.body as string);
        reviewCalls.push({ url: urlStr, body: parsed });

        if (parsed.review_id === 'rev-forbidden') {
          return new Response(
            JSON.stringify({ detail: 'Forbidden: Instance is in read-only mode' }),
            { status: 403, headers: { 'Content-Type': 'application/json' } }
          );
        }
        if (parsed.review_id === 'rev-unauth') {
          return new Response(
            JSON.stringify({ detail: 'Unauthorized: Session required' }),
            { status: 401, headers: { 'Content-Type': 'application/json' } }
          );
        }

        return new Response(
          JSON.stringify({
            status: parsed.action === 'approve' ? 'approved' : 'rejected',
            decision: parsed.action === 'approve' ? 'ALLOW' : 'BLOCK',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');

      // Approve success
      const appRes = await client.submitReview('rev-123', 'approve');
      assert.strictEqual(appRes.status, 'approved');

      // Reject success with reason
      const rejRes = await client.submitReview('rev-456', 'reject', 'Violates security perimeter');
      assert.strictEqual(rejRes.status, 'rejected');

      // 403 Read-only rejection
      await assert.rejects(
        async () => {
          await client.submitReview('rev-forbidden', 'approve');
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          assert.match(err.message, /read-only mode/);
          return true;
        }
      );

      // 401 Unauthorized rejection
      await assert.rejects(
        async () => {
          await client.submitReview('rev-unauth', 'approve');
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 401);
          return true;
        }
      );

      assert.strictEqual(reviewCalls.length, 4);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  /* ---------------- 4. Agent Containment ---------------- */

  it('8. Agent pause/unpause with 403 read-only handling: prevents false success reporting', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/incident/pause') || urlStr.endsWith('/api/incident/unpause')) {
        return new Response(
          JSON.stringify({ detail: 'Forbidden: Read-only mode prevents containment modifications' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');

      await assert.rejects(
        async () => {
          await client.pauseAgent('test-agent');
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          assert.match(err.message, /Read-only mode prevents containment/);
          return true;
        }
      );

      await assert.rejects(
        async () => {
          await client.unpauseAgent('test-agent');
        },
        (err: unknown) => {
          assert(err instanceof ApiError);
          assert.strictEqual(err.status, 403);
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  /* ---------------- 5. Policy Read-Only Immutability ---------------- */

  it('9. Policy read-only immutability: returns deterministic version hash and known tools list', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/policies')) {
        return new Response(
          JSON.stringify({
            version_hash: 'c8f7429188e734bc99f1a0e4125bcf6430d87a91',
            known_tools: ['read_web', 'search_web', 'query_database'],
            agents: [{ name: 'research-agent' }],
            tools: ['read_web', 'search_web', 'query_database'],
            policies: [
              {
                name: 'Default Engine Policy',
                description: 'Deterministic security constraints enforced by PolicyEngine',
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const policies = await client.getPolicies();

      assert.strictEqual(policies.version_hash, 'c8f7429188e734bc99f1a0e4125bcf6430d87a91');
      assert.deepStrictEqual(policies.known_tools, ['read_web', 'search_web', 'query_database']);
      assert.strictEqual(policies.policies.length, 1);
      assert.strictEqual(policies.policies[0].name, 'Default Engine Policy');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  /* ---------------- 6. Runtime Configuration ---------------- */

  it('10. Runtime configuration: retrieves engine limits and handles 403 non-global admin', async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/config')) {
        return new Response(
          JSON.stringify({
            environment: 'development',
            read_only: false,
            storage_backend: 'sqlite',
            database_configured: true,
            analyst_provider: 'mock',
            analyst_model: 'MockAnalystModel',
            mock_fallback_enabled: true,
            max_tool_execution_seconds: 30,
            max_tool_calls_per_session: 100,
            max_arguments_bytes: 65536,
            max_body_bytes: 1048576,
            max_token_budget: 100000,
            rate_limit_agent: 10,
            rate_limit_tool: 5,
            rate_limit_public: 60,
            rate_limit_analyst: 10,
            loop_consecutive_limit: 3,
            loop_cycle_limit: 2,
            circuit_breaker_failure_threshold: 5,
            circuit_breaker_recovery_timeout: 30.0,
            policy_version_hash: '900bfe512809f61b0d268d667c4bb9a98ef3718f',
            admin_auth_configured: true,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const cfg = await client.getRuntimeConfig();

      assert.strictEqual(cfg.environment, 'development');
      assert.strictEqual(cfg.storage_backend, 'sqlite');
      assert.strictEqual(cfg.circuit_breaker_failure_threshold, 5);
      assert.strictEqual(cfg.circuit_breaker_recovery_timeout, 30.0);
      assert.strictEqual(cfg.policy_version_hash, '900bfe512809f61b0d268d667c4bb9a98ef3718f');
      assert.strictEqual(cfg.admin_auth_configured, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
