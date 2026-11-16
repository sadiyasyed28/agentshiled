import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api/client.ts";

test("ApiClient register - handles self-service onboarding response", async () => {
  const mockPayload = {
    status: "created",
    tenant_id: "t_acme123",
    name: "Acme Corp",
    email: "dev@acme.com",
    api_key: "ash_live_secretToken1234567890",
    key_id: "key_abc",
    masked_key: "ash_live_...7890",
    csrf_token: "csrf_tok_1",
    created_at: 1700000000,
  };

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.includes("/api/auth/register")) {
        assert.equal(init?.method, "POST");
        const body = JSON.parse(String(init?.body));
        assert.equal(body.name, "Acme Corp");
        assert.equal(body.email, "dev@acme.com");
        return new Response(JSON.stringify(mockPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("Not Found", { status: 404 });
    };

    const client = new ApiClient("http://127.0.0.1:8000");
    const res = await client.register("Acme Corp", "dev@acme.com", "SecurePassword123!");

    assert.equal(res.status, "created");
    assert.equal(res.tenant_id, "t_acme123");
    assert.equal(res.api_key, "ash_live_secretToken1234567890");
    assert.equal(res.masked_key, "ash_live_...7890");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("ApiClient getApiKeys - retrieves masked keys for tenant", async () => {
  const mockPayload = {
    keys: [
      {
        key_id: "key_1",
        tenant_id: "t_acme123",
        name: "Production Agent",
        prefix: "ash_live",
        last_four: "4a9f",
        masked_key: "ash_live_...4a9f",
        created_at: 1700000000,
        revoked_at: null,
        last_used_at: 1700000500,
        is_active: true,
      },
    ],
    total: 1,
  };

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url: string | URL | Request) => {
      const urlStr = String(url);
      if (urlStr.includes("/api/api-keys")) {
        return new Response(JSON.stringify(mockPayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("Not Found", { status: 404 });
    };

    const client = new ApiClient("http://127.0.0.1:8000");
    const res = await client.getApiKeys();

    assert.equal(res.total, 1);
    assert.equal(res.keys[0].name, "Production Agent");
    assert.equal(res.keys[0].masked_key, "ash_live_...4a9f");
    assert.equal(res.keys[0].is_active, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("ApiClient rotateApiKey and revokeApiKey - lifecycle actions", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url: string | URL | Request, init?: RequestInit) => {
      const urlStr = String(url);
      if (urlStr.includes("/rotate")) {
        assert.equal(init?.method, "POST");
        return new Response(
          JSON.stringify({
            status: "rotated",
            key_id: "key_2",
            tenant_id: "t_acme123",
            name: "Rotated Key",
            masked_key: "ash_live_...9999",
            api_key: "ash_live_newSecret9999",
            created_at: 1700001000,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      if (urlStr.includes("/revoke")) {
        assert.equal(init?.method, "POST");
        return new Response(
          JSON.stringify({ status: "revoked", key_id: "key_1" }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("Not Found", { status: 404 });
    };

    const client = new ApiClient("http://127.0.0.1:8000");
    const rot = await client.rotateApiKey("key_1");
    assert.equal(rot.status, "rotated");
    assert.equal(rot.api_key, "ash_live_newSecret9999");

    const rev = await client.revokeApiKey("key_2");
    assert.equal(rev.status, "revoked");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

