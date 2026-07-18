import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveExternalCommunicationRoutesModulePath } from './index.js';

test('uses TypeScript route module while running from src in development', () => {
  const path = resolveExternalCommunicationRoutesModulePath(
    'file:///D:/wpa/wpa_auth/wpa_auth_api/src/routes/index.ts',
    'development',
  );

  assert.equal(path, '../modules/communication/events.routes.ts');
});

test('uses JavaScript route module while running from dist even in development', () => {
  const path = resolveExternalCommunicationRoutesModulePath(
    'file:///D:/wpa/wpa_auth/wpa_auth_api/dist/routes/index.js',
    'development',
  );

  assert.equal(path, '../modules/communication/events.routes.js');
});

test('uses JavaScript route module in production', () => {
  const path = resolveExternalCommunicationRoutesModulePath(
    'file:///D:/wpa/wpa_auth/wpa_auth_api/src/routes/index.ts',
    'production',
  );

  assert.equal(path, '../modules/communication/events.routes.js');
});
