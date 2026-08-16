import { OAuthProvider } from '@prisma/client';
import { config } from '../../config/index.js';
import { prisma } from '../../lib/db.js';
import { decryptCredentialPayload } from '../../lib/credentialEncryption.js';
import { logger } from '../../lib/logger.js';

export const FACEBOOK_GRAPH_API_VERSION = 'v26.0';

export function getFacebookGraphApiVersion() {
  return FACEBOOK_GRAPH_API_VERSION;
}

export function getFacebookAuthorizationUrl() {
  return `https://www.facebook.com/${FACEBOOK_GRAPH_API_VERSION}/dialog/oauth`;
}

export function getFacebookTokenUrl() {
  return `https://graph.facebook.com/${FACEBOOK_GRAPH_API_VERSION}/oauth/access_token`;
}

export function getFacebookUserInfoUrl() {
  return `https://graph.facebook.com/${FACEBOOK_GRAPH_API_VERSION}/me?fields=id,name,email,picture`;
}

export async function resolveFacebookAppCredentials(): Promise<{ appId: string; appSecret: string; source: 'db' | 'env' } | null> {
  const dbRow = await prisma.socialIdentityProviderConfig.findUnique({
    where: { provider: OAuthProvider.FACEBOOK },
    select: { clientId: true, clientSecretEncrypted: true, updatedAt: true },
  });

  const appId = dbRow?.clientId?.trim();
  const encryptedSecret = dbRow?.clientSecretEncrypted?.trim();
  if (appId && encryptedSecret) {
    try {
      const payload = decryptCredentialPayload(JSON.parse(encryptedSecret)) as { clientSecret?: string };
      const appSecret = payload.clientSecret?.trim();
      if (appSecret) return { appId, appSecret, source: 'db' };
    } catch (error) {
      logger.error({ error: error instanceof Error ? error.message : String(error), updatedAt: dbRow?.updatedAt?.toISOString?.() }, 'Failed to decrypt Facebook provider credentials from DB');
    }
  }

  const envAppId = config.FACEBOOK_APP_ID?.trim();
  const envAppSecret = config.FACEBOOK_APP_SECRET?.trim();
  if (envAppId && envAppSecret) {
    return { appId: envAppId, appSecret: envAppSecret, source: 'env' };
  }

  return null;
}
