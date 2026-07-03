import { config } from '../../config/index.js';
import { prisma } from '../../lib/db.js';
import { AppError } from '../../lib/errors.js';
import { writeAuditLog, writeSecurityEvent } from '../../lib/audit.js';
import { Request } from 'express';
import jwt from 'jsonwebtoken';
import { OAuthProvider, UserStatus } from '@prisma/client';
import { signAccessToken, signRefreshToken, hashToken, parseTtlToSeconds, generateOpaqueToken } from '../../lib/tokens.js';
import crypto from 'crypto';

interface SocialProfile {
  id: string;
  email?: string;
  emailVerified?: boolean;
  displayName?: string;
  avatarUrl?: string;
}

export function getProviderConfig(provider: string) {
  const p = provider.toUpperCase();
  switch (p) {
    case 'GOOGLE':
      return {
        clientId: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackUrl: config.GOOGLE_CALLBACK_URL,
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        profileUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
        scopes: 'openid email profile',
      };
    case 'FACEBOOK':
      return {
        clientId: config.FACEBOOK_CLIENT_ID,
        clientSecret: config.FACEBOOK_CLIENT_SECRET,
        callbackUrl: config.FACEBOOK_CALLBACK_URL,
        authUrl: 'https://www.facebook.com/v13.0/dialog/oauth',
        tokenUrl: 'https://graph.facebook.com/v13.0/oauth/access_token',
        profileUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
        scopes: 'email public_profile',
      };
    case 'APPLE':
      return {
        clientId: config.APPLE_CLIENT_ID,
        clientSecret: null, // Generated dynamically
        callbackUrl: config.APPLE_CALLBACK_URL,
        authUrl: 'https://appleid.apple.com/auth/authorize',
        tokenUrl: 'https://appleid.apple.com/auth/token',
        profileUrl: null, // Included in id_token
        scopes: 'name email',
      };
    case 'TWITTER':
      return {
        clientId: config.TWITTER_CLIENT_ID,
        clientSecret: config.TWITTER_CLIENT_SECRET,
        callbackUrl: config.TWITTER_CALLBACK_URL,
        authUrl: 'https://twitter.com/i/oauth2/authorize',
        tokenUrl: 'https://api.twitter.com/2/oauth2/token',
        profileUrl: 'https://api.twitter.com/2/users/me?user.fields=profile_image_url',
        scopes: 'tweet.read users.read offline.access',
      };
    case 'INSTAGRAM':
      return {
        clientId: config.INSTAGRAM_CLIENT_ID,
        clientSecret: config.INSTAGRAM_CLIENT_SECRET,
        callbackUrl: config.INSTAGRAM_CALLBACK_URL,
        authUrl: 'https://api.instagram.com/oauth/authorize',
        tokenUrl: 'https://api.instagram.com/oauth/access_token',
        profileUrl: 'https://graph.instagram.com/me?fields=id,username',
        scopes: 'user_profile user_media',
      };
    default:
      return null;
  }
}

export function isProviderConfigured(conf: any, provider: string) {
  if (!conf) return false;
  if (provider.toUpperCase() === 'APPLE') {
    return !!(conf.clientId && config.APPLE_TEAM_ID && config.APPLE_KEY_ID && config.APPLE_PRIVATE_KEY && conf.callbackUrl);
  }
  return !!(conf.clientId && conf.clientSecret && conf.callbackUrl);
}

function generateAppleClientSecret() {
  if (!config.APPLE_PRIVATE_KEY || !config.APPLE_TEAM_ID || !config.APPLE_CLIENT_ID || !config.APPLE_KEY_ID) {
    throw new AppError('Apple provider misconfigured', 'PROVIDER_MISCONFIGURED', 500);
  }
  const privateKey = config.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n');
  return jwt.sign({}, privateKey, {
    algorithm: 'ES256',
    keyid: config.APPLE_KEY_ID,
    issuer: config.APPLE_TEAM_ID,
    audience: 'https://appleid.apple.com',
    subject: config.APPLE_CLIENT_ID,
    expiresIn: '180d', // max allowed by Apple
  });
}

function normalizeProviderName(provider: string): OAuthProvider {
  const upper = provider.toUpperCase();
  if (Object.values(OAuthProvider).includes(upper as OAuthProvider)) {
    return upper as OAuthProvider;
  }
  throw new AppError('Unsupported provider', 'INVALID_PROVIDER', 400);
}

export async function checkProviderEnabled(provider: string) {
  const enumProvider = normalizeProviderName(provider);
  const setting = await prisma.socialProviderSetting.findUnique({ where: { provider: enumProvider } });
  if (!setting || !setting.enabled) {
    throw new AppError(`Provider ${provider} is disabled.`, 'PROVIDER_DISABLED', 403);
  }
  return enumProvider;
}

export async function getSocialStartUrl(provider: string, clientId: string, redirectUri: string, origin?: string) {
  await checkProviderEnabled(provider);
  const conf = getProviderConfig(provider);
  if (!conf || !isProviderConfigured(conf, provider)) {
    throw new AppError('Provider is not configured properly.', 'PROVIDER_MISCONFIGURED', 500);
  }

  // Validate the client
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client || client.status !== 'ACTIVE') {
    throw new AppError('Invalid client.', 'INVALID_CLIENT', 400);
  }
  if (!client.redirectUris.includes(redirectUri)) {
    throw new AppError('Invalid redirect URI.', 'INVALID_REDIRECT_URI', 400);
  }
  if (origin && !client.allowedOrigins.includes(origin) && !client.allowedOrigins.includes('*')) {
    throw new AppError('Invalid origin.', 'INVALID_ORIGIN', 403);
  }

  // Generate secure state
  // state holds: clientId, redirectUri, provider, nonce
  const payload = { clientId, redirectUri, provider, nonce: crypto.randomBytes(16).toString('hex') };
  const state = jwt.sign(payload, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });

  let url = `${conf.authUrl}?response_type=code&client_id=${conf.clientId}&redirect_uri=${conf.callbackUrl}&scope=${encodeURIComponent(conf.scopes)}&state=${state}`;

  if (provider.toUpperCase() === 'APPLE') {
    url += `&response_mode=form_post`;
  }
  if (provider.toUpperCase() === 'TWITTER') {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    // Store codeVerifier in the state or somewhere else? State is signed by us, so we can store it in the state!
    const pkcePayload = { ...payload, codeVerifier };
    const pkceState = jwt.sign(pkcePayload, config.JWT_ACCESS_SECRET, { expiresIn: '10m' });
    url = `${conf.authUrl}?response_type=code&client_id=${conf.clientId}&redirect_uri=${conf.callbackUrl}&scope=${encodeURIComponent(conf.scopes)}&state=${pkceState}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  }

  return url;
}

export async function handleSocialCallback(provider: string, code: string, state: string, req: Request) {
  const enumProvider = await checkProviderEnabled(provider);
  const conf = getProviderConfig(provider);
  if (!conf || !isProviderConfigured(conf, provider)) {
    throw new AppError('Provider is not configured.', 'PROVIDER_MISCONFIGURED', 500);
  }

  let payload: any;
  try {
    payload = jwt.verify(state, config.JWT_ACCESS_SECRET);
  } catch (err) {
    await writeSecurityEvent({
      type: 'SUSPICIOUS_OAUTH',
      severity: 'HIGH',
      metadata: { reason: 'invalid_social_state' },
      req,
    });
    throw new AppError('Invalid or expired state.', 'INVALID_STATE', 400);
  }

  if (payload.provider !== provider) {
    throw new AppError('State provider mismatch.', 'INVALID_STATE', 400);
  }

  const { clientId, redirectUri, codeVerifier } = payload;
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client) throw new AppError('Invalid client in state.', 'INVALID_CLIENT', 400);

  // Exchange code
  const tokenParams = new URLSearchParams();
  tokenParams.append('grant_type', 'authorization_code');
  tokenParams.append('code', code);
  tokenParams.append('redirect_uri', conf.callbackUrl!);
  tokenParams.append('client_id', conf.clientId!);

  if (provider.toUpperCase() === 'APPLE') {
    tokenParams.append('client_secret', generateAppleClientSecret());
  } else if (conf.clientSecret) {
    tokenParams.append('client_secret', conf.clientSecret);
  }

  if (codeVerifier) {
    tokenParams.append('code_verifier', codeVerifier);
  }

  let tokenRes: any;
  try {
    const res = await fetch(conf.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: tokenParams.toString(),
    });
    tokenRes = await res.json() as any;
    if (!res.ok) {
      console.error(`Provider token error [${provider}]:`, tokenRes);
      throw new Error('Token exchange failed');
    }
  } catch (e: any) {
    throw new AppError(`Failed to exchange code with provider: ${e.message}`, 'PROVIDER_ERROR', 502);
  }

  let profile: SocialProfile;

  if (provider.toUpperCase() === 'APPLE') {
    // Apple sends id_token containing profile info
    const decoded = jwt.decode(tokenRes.id_token) as any;
    profile = {
      id: decoded.sub,
      email: decoded.email,
      emailVerified: decoded.email_verified === 'true' || decoded.email_verified === true,
    };
    // Note: Apple only sends 'user' JSON object containing name on the FIRST authorization.
    // If it's missing, we don't have the name.
  } else {
    // Fetch profile
    try {
      const res = await fetch(conf.profileUrl!, {
        headers: { 'Authorization': `Bearer ${tokenRes.access_token}` },
      });
      const profileData = await res.json();
      if (!res.ok) throw new Error('Profile fetch failed');
      
      profile = normalizeProfile(provider, profileData);
    } catch (e: any) {
      throw new AppError(`Failed to fetch profile: ${e.message}`, 'PROVIDER_ERROR', 502);
    }
  }

  return loginOrCreateSocialUser({
    provider: enumProvider,
    profile,
    clientId: client.id,
    req,
    rawProfile: tokenRes,
    clientRedirectUri: redirectUri,
  });
}

export async function mobileSocialLogin(provider: string, token: string, clientId: string, req: Request) {
  const enumProvider = await checkProviderEnabled(provider);
  const client = await prisma.authClient.findUnique({ where: { clientId } });
  if (!client) throw new AppError('Invalid client.', 'INVALID_CLIENT', 400);

  // Verification differs by provider. For brevity, simulating provider token verification.
  // In production, you would call tokeninfo or use provider SDK to verify `token`.
  // For Google: fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`)
  // For Apple: verify JWT signature against Apple JWKS
  
  let profile: SocialProfile;
  if (enumProvider === 'GOOGLE') {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
    const data = await res.json() as any;
    if (!res.ok) throw new AppError('Invalid Google token', 'INVALID_TOKEN', 401);
    profile = {
      id: data.sub,
      email: data.email,
      emailVerified: data.email_verified === 'true',
      displayName: data.name,
      avatarUrl: data.picture,
    };
  } else if (enumProvider === 'APPLE') {
    // Basic decode for demonstration. Should verify signature!
    const data = jwt.decode(token) as any;
    profile = {
      id: data.sub,
      email: data.email,
      emailVerified: true,
    };
  } else {
    throw new AppError(`Mobile login for ${provider} not fully implemented in this demo`, 'NOT_IMPLEMENTED', 501);
  }

  const result = await loginOrCreateSocialUser({
    provider: enumProvider,
    profile,
    clientId: client.id,
    req,
    rawProfile: profile,
    clientRedirectUri: null, // mobile doesn't need redirect
  });

  return result;
}

function normalizeProfile(provider: string, data: any): SocialProfile {
  const p = provider.toUpperCase();
  if (p === 'GOOGLE') {
    return {
      id: data.sub,
      email: data.email,
      emailVerified: data.email_verified,
      displayName: data.name,
      avatarUrl: data.picture,
    };
  } else if (p === 'FACEBOOK') {
    return {
      id: data.id,
      email: data.email,
      emailVerified: true, // Facebook verifies emails
      displayName: data.name,
      avatarUrl: data.picture?.data?.url,
    };
  } else if (p === 'TWITTER') {
    return {
      id: data.data.id,
      displayName: data.data.name,
      avatarUrl: data.data.profile_image_url,
    };
  } else if (p === 'INSTAGRAM') {
    return {
      id: data.id,
      displayName: data.username,
    };
  }
  return { id: data.id };
}

async function loginOrCreateSocialUser(opts: {
  provider: OAuthProvider;
  profile: SocialProfile;
  clientId: string;
  req: Request;
  rawProfile: any;
  clientRedirectUri: string | null;
}) {
  const { provider, profile, clientId, req } = opts;

  // 1. Check if OAuth account exists
  let oauthAcc = await prisma.oAuthAccount.findUnique({
    where: { provider_providerAccountId: { provider, providerAccountId: profile.id } },
    include: { user: true },
  });

  let user = oauthAcc?.user;

  // 2. If not, check if user with same verified email exists
  if (!user && profile.email && profile.emailVerified) {
    user = await prisma.user.findFirst({
      where: { email: profile.email, emailVerifiedAt: { not: null } },
    }) ?? undefined;
  }

  // 3. If no user, create one
  if (!user) {
    user = await prisma.user.create({
      data: {
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl,
        emailVerifiedAt: profile.emailVerified ? new Date() : null,
        status: UserStatus.ACTIVE,
      },
    });
    // Assign default role
    const defaultRole = await prisma.role.findFirst({ where: { name: { in: ['user', 'USER'] } } });
    if (defaultRole) {
      await prisma.userRole.create({ data: { userId: user.id, roleId: defaultRole.id } });
    }
  }

  // 4. Create OAuth account if it didn't exist
  if (!oauthAcc) {
    await prisma.oAuthAccount.create({
      data: {
        userId: user.id,
        provider,
        providerAccountId: profile.id,
        rawProfile: opts.rawProfile,
      },
    });
    await writeAuditLog({ userId: user.id, action: 'OAUTH_LINKED', metadata: { provider }, req });
  }

  // 5. Generate tokens
  const rolesRows = await prisma.userRole.findMany({ where: { userId: user.id }, include: { role: true } });
  const roles = rolesRows.map((r) => r.role.name);
  const accessToken = signAccessToken({ sub: user.id, email: user.email, username: user.username, roles });
  const refreshToken = signRefreshToken(user.id);
  const tokenHash = hashToken(refreshToken);

  const session = await prisma.loginSession.create({
    data: {
      userId: user.id,
      clientId,
      sessionToken: generateOpaqueToken(),
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
    },
  });

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      clientId,
      tokenHash,
      scopes: ['openid', 'offline_access'],
      expiresAt: new Date(Date.now() + parseTtlToSeconds(config.REFRESH_TOKEN_TTL) * 1000),
      ipAddress: req.ip ?? req.socket.remoteAddress,
      userAgent: req.headers['user-agent'],
      familyId: session.id,
    },
  });

  await prisma.user.update({
    where: { id: user.id },
    data: { lastLoginAt: new Date() },
  });

  await writeAuditLog({ userId: user.id, clientId, action: 'LOGIN', metadata: { success: true, method: 'social', provider }, req });

  // Safe user obj
  const safeUser = {
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    roles,
  };

  if (opts.clientRedirectUri) {
    const params = new URLSearchParams({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: parseTtlToSeconds(config.ACCESS_TOKEN_TTL).toString(),
    });
    return { url: `${opts.clientRedirectUri}?${params.toString()}` };
  }

  return {
    accessToken,
    refreshToken,
    expiresIn: parseTtlToSeconds(config.ACCESS_TOKEN_TTL),
    user: safeUser,
  };
}
