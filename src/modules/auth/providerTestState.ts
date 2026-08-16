import jwt from 'jsonwebtoken';
import { OAuthProvider } from '@prisma/client';
import { config } from '../../config/index.js';
import { AppError } from '../../lib/errors.js';
import { generateOpaqueToken } from '../../lib/tokens.js';
import { getRedisClient } from '../../lib/redis.js';

const ADMIN_PROVIDER_TEST_TTL_SECONDS = 10 * 60;
const ADMIN_PROVIDER_TEST_PREFIX = 'social:admin-provider-test:';

export type AdminProviderTestStateContext = {
  provider: OAuthProvider;
  providerConfigId: string;
  adminId: string;
  returnTo: string;
  codeVerifier?: string | null;
  testRunId: string;
  createdAt: string;
};

const memoryStore = new Map<string, { expiresAt: number; value: AdminProviderTestStateContext }>();

function redisKey(nonce: string) {
  return `${ADMIN_PROVIDER_TEST_PREFIX}${nonce}`;
}

function storeInMemory(nonce: string, value: AdminProviderTestStateContext) {
  memoryStore.set(nonce, {
    expiresAt: Date.now() + ADMIN_PROVIDER_TEST_TTL_SECONDS * 1000,
    value,
  });
}

function consumeFromMemory(nonce: string) {
  const entry = memoryStore.get(nonce);
  if (!entry) return null;
  memoryStore.delete(nonce);
  if (Date.now() > entry.expiresAt) return null;
  return entry.value;
}

async function persistContext(nonce: string, value: AdminProviderTestStateContext) {
  const redis = getRedisClient();
  if (redis) {
    await redis.set(redisKey(nonce), JSON.stringify(value), 'EX', ADMIN_PROVIDER_TEST_TTL_SECONDS);
    return;
  }
  storeInMemory(nonce, value);
}

async function consumeContext(nonce: string) {
  const redis = getRedisClient();
  if (redis) {
    const key = redisKey(nonce);
    const raw = await redis.get(key);
    if (!raw) return null;
    await redis.del(key);
    try {
      return JSON.parse(raw) as AdminProviderTestStateContext;
    } catch {
      return null;
    }
  }
  return consumeFromMemory(nonce);
}

export async function createAdminProviderTestState(context: AdminProviderTestStateContext): Promise<string> {
  if (!context.providerConfigId || !context.adminId || !context.returnTo) {
    throw new AppError('Provider test context is incomplete.', 'PROVIDER_MISCONFIGURED', 400);
  }
  const nonce = generateOpaqueToken(16);
  await persistContext(nonce, context);
  return jwt.sign(
    { provider: context.provider, purpose: 'ADMIN_PROVIDER_TEST', nonce },
    config.JWT_ACCESS_SECRET,
    { expiresIn: '10m' },
  );
}

export async function consumeAdminProviderTestState(nonce?: string | null) {
  if (!nonce) return null;
  return consumeContext(nonce);
}
