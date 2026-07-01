import crypto from 'crypto';
import { config } from '../config/index.js';

type EncryptedPayload = {
  iv: string;
  authTag: string;
  ciphertext: string;
};

function getKey() {
  const raw = config.CREDENTIAL_ENCRYPTION_KEY;
  if (/^[a-f0-9]{64}$/i.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  return crypto.createHash('sha256').update(raw).digest();
}

export function encryptCredentialPayload(payload: Record<string, unknown>): EncryptedPayload {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

export function decryptCredentialPayload(payload: EncryptedPayload): Record<string, unknown> {
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');

  return JSON.parse(plaintext);
}

export function maskSecret(value?: string | null) {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.includes('@')) return trimmed;
  if (trimmed.length <= 4) return '****';
  return `${'*'.repeat(Math.max(8, trimmed.length - 4))}${trimmed.slice(-4)}`;
}
