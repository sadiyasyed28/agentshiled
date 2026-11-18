import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ApiClient, ApiError } from '../src/api/client.ts';

describe('Phase 1: Real Authentication & Session Integration', () => {
  it('1. Initial unauthenticated state: getSession reports authenticated: false', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/session')) {
        return new Response(
          JSON.stringify({
            authenticated: false,
            read_only: false,
            admin_configured: true,
            expires_at: null,
            csrf_token: null,
            tenant_id: 'default',
            role: 'tenant_admin',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      let emittedSession = null;
      const unsub = client.onAuthChange((s) => {
        emittedSession = s;
      });

      const session = await client.getSession();
      assert.strictEqual(session.authenticated, false);
      assert.strictEqual(session.csrf_token, null);
      assert.strictEqual(session.admin_configured, true);
      assert.strictEqual(emittedSession, session);
      unsub();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('2. Successful login: posts admin_key and captures CSRF token and session', async () => {
    let capturedBody: string | null = null;
    let capturedMethod: string | null = null;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/login')) {
        capturedMethod = init?.method || null;
        capturedBody = init?.body as string;
        return new Response(
          JSON.stringify({
            status: 'authenticated',
            authenticated: true,
            expires_at: 1799999999,
            csrf_token: 'test-csrf-token-abc-123',
            read_only: false,
            tenant_id: 'default',
            role: 'global_admin',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      let authChangeCalled = false;
      client.onAuthChange((s) => {
        if (s?.authenticated) authChangeCalled = true;
      });

      const res = await client.login('super-admin-secret-key-xyz');
      assert.strictEqual(res.authenticated, true);
      assert.strictEqual(res.role, 'global_admin');
      assert.strictEqual(res.csrf_token, 'test-csrf-token-abc-123');
      assert.strictEqual(capturedMethod, 'POST');
      assert.deepStrictEqual(JSON.parse(capturedBody!), { admin_key: 'super-admin-secret-key-xyz' });
      assert.strictEqual(authChangeCalled, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('3. Failed login: invalid credentials throw ApiError with status 401', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      if (url.toString().endsWith('/api/auth/login')) {
        return new Response(
          JSON.stringify({ detail: 'Unauthorized: Invalid administrative credentials' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      await assert.rejects(
        async () => {
          await client.login('wrong-admin-key');
        },
        (err: ApiError) => {
          assert.strictEqual(err.status, 401);
          assert.strictEqual(err.isAuthError, true);
          assert.ok(err.message.includes('Invalid administrative credentials'));
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('4. Session restoration: getSession restores active session and CSRF token', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      if (url.toString().endsWith('/api/auth/session')) {
        return new Response(
          JSON.stringify({
            authenticated: true,
            read_only: false,
            admin_configured: true,
            expires_at: 1800000000,
            csrf_token: 'restored-csrf-token-999',
            tenant_id: 'tenant-finance',
            role: 'tenant_admin',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      const session = await client.getSession();
      assert.strictEqual(session.authenticated, true);
      assert.strictEqual(session.role, 'tenant_admin');
      assert.strictEqual(session.tenant_id, 'tenant-finance');
      assert.strictEqual(session.csrf_token, 'restored-csrf-token-999');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('5. Logout: calls /api/auth/logout and clears CSRF token and session', async () => {
    let logoutCalled = false;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/logout')) {
        logoutCalled = true;
        assert.strictEqual(init?.method, 'POST');
        return new Response(
          JSON.stringify({ status: 'logged_out', authenticated: false, read_only: false }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      let loggedOutNotification = false;
      client.onAuthChange((s) => {
        if (s === null) loggedOutNotification = true;
      });

      const res = await client.logout();
      assert.strictEqual(res.status, 'logged_out');
      assert.strictEqual(logoutCalled, true);
      assert.strictEqual(loggedOutNotification, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('6. CSRF-protected operations: mutating actions include x-csrf-token from session', async () => {
    let capturedHeaders: Headers | null = null;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/login')) {
        return new Response(
          JSON.stringify({
            status: 'authenticated',
            authenticated: true,
            csrf_token: 'csrf-double-submit-secret-777',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/incident/unpause')) {
        capturedHeaders = new Headers(init?.headers);
        return new Response(
          JSON.stringify({ agent: 'worker-agent', status: 'active' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');
      await client.login('admin-key-123');

      const unpauseRes = await client.unpauseAgent('worker-agent');
      assert.strictEqual(unpauseRes.status, 'active');
      assert.strictEqual(
        capturedHeaders?.get('x-csrf-token'),
        'csrf-double-submit-secret-777'
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('7. 401 and 403 handling: distinguish between unauthenticated and forbidden', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/unauth')) {
        return new Response(JSON.stringify({ detail: 'Unauthorized: Invalid administrative credentials' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (urlStr.endsWith('/api/forbidden')) {
        return new Response(JSON.stringify({ detail: 'Forbidden: API is in read-only mode for incident controls' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');

      await assert.rejects(
        async () => {
          await client['request']('/api/unauth');
        },
        (err: ApiError) => {
          assert.strictEqual(err.status, 401);
          assert.strictEqual(err.isAuthError, true);
          assert.strictEqual(err.isForbidden, false);
          return true;
        }
      );

      await assert.rejects(
        async () => {
          await client['request']('/api/forbidden');
        },
        (err: ApiError) => {
          assert.strictEqual(err.status, 403);
          assert.strictEqual(err.isAuthError, false);
          assert.strictEqual(err.isForbidden, true);
          return true;
        }
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('8. Protected actions becoming available after authentication', async () => {
    let isAuthenticated = false;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.endsWith('/api/auth/login')) {
        isAuthenticated = true;
        return new Response(
          JSON.stringify({
            status: 'authenticated',
            authenticated: true,
            csrf_token: 'csrf-active-token',
            role: 'global_admin',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (urlStr.endsWith('/api/policies')) {
        if (!isAuthenticated) {
          return new Response(
            JSON.stringify({ detail: 'Unauthorized: Invalid administrative credentials' }),
            { status: 401, headers: { 'Content-Type': 'application/json' } }
          );
        }
        return new Response(
          JSON.stringify({
            version_hash: 'hash-abc-123',
            known_tools: ['read_file', 'write_file'],
            agents: [],
            tools: [],
            policies: [],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    };

    try {
      const client = new ApiClient('http://localhost:8000');

      // 1. Before login: getPolicies fails with 401
      await assert.rejects(
        async () => {
          await client.getPolicies();
        },
        (err: ApiError) => {
          assert.strictEqual(err.status, 401);
          return true;
        }
      );

      // 2. Perform login
      const loginRes = await client.login('correct-admin-key');
      assert.strictEqual(loginRes.authenticated, true);

      // 3. After login: getPolicies succeeds with 200
      const policies = await client.getPolicies();
      assert.strictEqual(policies.version_hash, 'hash-abc-123');
      assert.deepStrictEqual(policies.known_tools, ['read_file', 'write_file']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

