import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const source = readFileSync(resolve(process.cwd(), 'src/modules/auth/social.service.ts'), 'utf8');

test('OAuth-mode social login does not require provider email before authorization-code continuation', () => {
  assert.match(source, /!user && !profile\.email && opts\?\.issueTokens !== false/);
  assert.match(source, /email: profile\.email \?\? null/);
  assert.match(source, /issueTokens: payload\.authMode === 'oauth' \? false : true/);
});
