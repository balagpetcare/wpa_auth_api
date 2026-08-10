// Prints ONLY status codes and response envelope/key shapes for the
// identity GET/PATCH routes and negative JWT verification — never actual
// field values (no names, emails, phones, tokens). Uses the real local dev
// database via a synthetic in-process user (created and cleaned up).
import { prisma } from '../src/lib/db.js';
import {
  getCurrentUser,
  updateCurrentUserProfile,
} from '../src/modules/auth/auth.service.js';
import { signAccessToken } from '../src/lib/tokens.js';
import type { Request } from 'express';

function keysOf(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.length > 0 ? [keysOf(value[0])] : [];
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = v && typeof v === 'object' ? keysOf(v) : typeof v;
    }
    return out;
  }
  return typeof value;
}

function fakeReq(): Request {
  return { ip: '127.0.0.1', socket: { remoteAddress: '127.0.0.1' }, headers: {} } as unknown as Request;
}

async function main() {
  const evidence: Record<string, unknown> = {};
  const user = await prisma.user.create({
    data: { email: `evidence-${Date.now()}@example.com`, status: 'ACTIVE' },
  });

  try {
    const identity = await getCurrentUser(user.id);
    evidence['getCurrentUser (GET /auth/me service layer)'] = {
      resultKeys: keysOf(identity),
    };

    const updated = await updateCurrentUserProfile(
      user.id,
      { firstName: 'Evidence', dateOfBirth: '1990-01-01' },
      fakeReq(),
    );
    evidence['updateCurrentUserProfile (PATCH /auth/me service layer)'] = {
      resultKeys: keysOf(updated),
    };

    // Negative JWT verification evidence: sign a token, then verify wrong
    // audience / expired / bad signature all fail as expected. Default
    // ACCESS_TOKEN_AUDIENCE in this dev env is "bpa-mobile" — that's the
    // one valid audience for a token signed with no explicit audience arg.
    const { verifyAccessToken } = await import('../src/lib/tokens.js');
    const jwt = (await import('jsonwebtoken')).default;

    const validToken = signAccessToken({ sub: user.id, roles: [] });
    try {
      verifyAccessToken(validToken);
      evidence['verifyAccessToken (valid token, correct audience)'] = { result: 'accepted (expected)' };
    } catch (e) {
      evidence['verifyAccessToken (valid token, correct audience)'] = {
        result: 'rejected',
        unexpected: true,
      };
    }

    try {
      const wrongAudienceToken = signAccessToken({ sub: user.id, roles: [] }, 'not-a-registered-client');
      verifyAccessToken(wrongAudienceToken);
      evidence['verifyAccessToken (invalid audience)'] = { result: 'accepted', unexpected: true };
    } catch (e) {
      evidence['verifyAccessToken (invalid audience)'] = { result: 'rejected (expected)' };
    }

    try {
      // Deliberately garbage signature.
      const parts = validToken.split('.');
      const tampered = `${parts[0]}.${parts[1]}.tamperedsignature`;
      verifyAccessToken(tampered);
      evidence['verifyAccessToken (bad signature)'] = { result: 'accepted', unexpected: true };
    } catch (e) {
      evidence['verifyAccessToken (bad signature)'] = { result: 'rejected (expected)' };
    }

    try {
      // Manually sign an already-expired token with the same secret/issuer.
      const expired = jwt.sign(
        { sub: user.id, roles: [] },
        process.env.JWT_ACCESS_SECRET ?? '',
        { expiresIn: -10, issuer: process.env.OAUTH_ISSUER, audience: 'bpa-mobile' },
      );
      verifyAccessToken(expired);
      evidence['verifyAccessToken (expired token)'] = { result: 'accepted', unexpected: true };
    } catch (e) {
      evidence['verifyAccessToken (expired token)'] = { result: 'rejected (expected)' };
    }
  } finally {
    await prisma.refreshToken.deleteMany({ where: { userId: user.id } });
    await prisma.loginSession.deleteMany({ where: { userId: user.id } });
    await prisma.user.delete({ where: { id: user.id } }).catch(() => undefined);
    await prisma.$disconnect();
  }

  process.stdout.write(JSON.stringify(evidence, null, 2) + '\n');
}

void main().catch((e) => {
  process.stderr.write(JSON.stringify({ error: String(e) }) + '\n');
  process.exitCode = 1;
});
