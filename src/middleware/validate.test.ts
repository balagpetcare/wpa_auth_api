import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import { z } from 'zod';
import { validateBody } from './validate.js';

async function startServer() {
  const app = express();
  app.use(express.json());
  app.post('/validate', validateBody(z.object({
    authorizationUrl: z.string().url(),
    tokenUrl: z.string().url(),
    redirectUri: z.string().url(),
  })), (_req, res) => {
    res.json({ success: true });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

test('validateBody returns a safe validation error shape with issues', async () => {
  const { server, baseUrl } = await startServer();
  try {
    const res = await fetch(`${baseUrl}/validate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        authorizationUrl: '',
        tokenUrl: '',
        redirectUri: '',
      }),
    });
    assert.equal(res.status, 400);
    const body = await res.json() as {
      success: boolean
      code: string
      message: string
      issues: Array<{ field: string; message: string }>
      errors: Array<{ field: string; message: string }>
    };
    assert.equal(body.success, false);
    assert.equal(body.code, 'VALIDATION_ERROR');
    assert.match(body.message, /authorizationUrl/);
    assert.ok(Array.isArray(body.issues));
    assert.deepEqual(body.issues.map((issue: { field: string }) => issue.field), ['authorizationUrl', 'tokenUrl', 'redirectUri']);
    assert.deepEqual(body.issues, body.errors);
  } finally {
    server.close();
  }
});

test('validateBody rejects an invalid social-provider status payload with VALIDATION_ERROR', async () => {
  const app = express();
  app.use(express.json());
  app.patch('/social-providers/:id/status', validateBody(z.object({ status: z.enum(['ACTIVE', 'INACTIVE']) })), (_req, res) => {
    res.json({ success: true });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/social-providers/provider-1/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ status: 'ENABLED' }),
    });
    assert.equal(res.status, 400);
    const body = await res.json() as { success: boolean; code: string; message: string; issues: Array<{ field: string; message: string }> };
    assert.equal(body.success, false);
    assert.equal(body.code, 'VALIDATION_ERROR');
    assert.match(body.message, /status/);
    assert.deepEqual(body.issues.map((issue) => issue.field), ['status']);
  } finally {
    server.close();
  }
});
