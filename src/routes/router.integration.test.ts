import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import apiRouter from './index.js';
import { errorHandler } from '../middleware/error.js';
import { config } from '../config/index.js';

async function startMountedApp() {
  const app = express();
  app.use(express.json());
  app.use(config.API_PREFIX, apiRouter);
  app.use(errorHandler);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('Failed to start test server.');
  }

  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
}

test('mounted application exposes OAuth/OIDC routes under the API prefix', async () => {
  const { server, baseUrl } = await startMountedApp();
  try {
    const discovery = await fetch(`${baseUrl}${config.API_PREFIX}/.well-known/openid-configuration`);
    assert.equal(discovery.status, 200);

    const jwks = await fetch(`${baseUrl}${config.API_PREFIX}/oauth/jwks`);
    assert.equal(jwks.status, 200);

    const authorize = await fetch(`${baseUrl}${config.API_PREFIX}/oauth/authorize`);
    assert.equal(authorize.status, 401);

    const token = await fetch(`${baseUrl}${config.API_PREFIX}/oauth/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(token.status, 400);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('unknown OAuth paths still return 404 on the mounted application router', async () => {
  const { server, baseUrl } = await startMountedApp();
  try {
    const res = await fetch(`${baseUrl}${config.API_PREFIX}/oauth/not-a-real-route`);
    assert.equal(res.status, 404);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
