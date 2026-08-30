import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { prisma } from '../../lib/db.js';
import { signAccessToken } from '../../lib/tokens.js';
import { config } from '../../config/index.js';

const API = `http://localhost:${config.PORT}${config.API_PREFIX}`;
const TEST_USER_ID = 'diag-test-user-authorize';

async function fetchJson(url: string, opts: RequestInit = {}): Promise<{ status: number; body: any }> {
  const res = await fetch(url, opts);
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

describe('OAuth authorize — INVALID_CLIENT status code (regression)', () => {
  // Regression: INVALID_CLIENT previously returned 401, which the web BFF's
  // apiClient treated as an expired access token — triggering refresh → retry
  // → still 401 → clear session → redirect-to-login → infinite login loop.
  // It must be 400 so the apiClient does NOT treat it as a token problem.
  it('returns 400 (not 401) for an unknown client_id', async () => {
    const token = signAccessToken({ sub: TEST_USER_ID, email: null, username: null, roles: [] });
    const { status, body } = await fetchJson(
      `${API}/oauth/authorize?response_type=code&client_id=nonexistent-client-id&redirect_uri=http://localhost:7500/callback&scope=openid`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    assert.strictEqual(status, 400);
    assert.strictEqual(body?.code, 'INVALID_CLIENT');
  });

  it('returns 401 when no access token is provided', async () => {
    const { status } = await fetchJson(
      `${API}/oauth/authorize?response_type=code&client_id=furtail-admin&redirect_uri=http://localhost:7500/api/auth/callback&scope=openid`,
    );
    assert.strictEqual(status, 401);
  });

  it('accepts a valid token + registered furtail-admin client + correct redirect_uri', async () => {
    const token = signAccessToken({ sub: TEST_USER_ID, email: null, username: null, roles: [] });
    const { status, body } = await fetchJson(
      `${API}/oauth/authorize?response_type=code&client_id=furtail-admin&redirect_uri=http://localhost:7500/api/auth/callback&scope=openid%20profile%20email&state=s1`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    assert.strictEqual(status, 200);
    assert.strictEqual(body?.success, true);
    assert.ok(body?.code, 'authorization code must be present');
    assert.strictEqual(body?.state, 's1');
  });

  it('rejects an unregistered redirect_uri with 400 INVALID_REDIRECT_URI', async () => {
    const token = signAccessToken({ sub: TEST_USER_ID, email: null, username: null, roles: [] });
    const { status, body } = await fetchJson(
      `${API}/oauth/authorize?response_type=code&client_id=furtail-admin&redirect_uri=http://evil.example/callback&scope=openid`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    assert.strictEqual(status, 400);
    assert.strictEqual(body?.code, 'INVALID_REDIRECT_URI');
  });

  it('rejects scopes not in the client allowedScopes with 400 INVALID_SCOPE', async () => {
    const token = signAccessToken({ sub: TEST_USER_ID, email: null, username: null, roles: [] });
    const { status, body } = await fetchJson(
      `${API}/oauth/authorize?response_type=code&client_id=furtail-admin&redirect_uri=http://localhost:7500/api/auth/callback&scope=openid%20admin`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    assert.strictEqual(status, 400);
    assert.strictEqual(body?.code, 'INVALID_SCOPE');
  });
});
