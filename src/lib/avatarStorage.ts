import crypto from 'crypto';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';

/**
 * Avatar storage — Backblaze B2 (S3-compatible). Previously wrote files to
 * local VPS disk (uploads/avatars/); migrated so no production uploads are
 * stored on the VPS. Function names/signatures kept stable so callers
 * (auth.routes.ts, auth.service.ts, admin.service.ts, deletion.service.ts)
 * needed minimal changes.
 */

const allowedMimeToExt: Record<string, string> = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};

function requiredEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required storage env var: ${name}`);
  return v;
}

function isConfigured(): boolean {
  return Boolean(
    process.env.S3_ENDPOINT &&
      process.env.S3_REGION &&
      process.env.S3_BUCKET &&
      process.env.S3_ACCESS_KEY &&
      process.env.S3_SECRET_KEY
  );
}

let client: S3Client | null = null;
function getClient(): S3Client {
  if (client) return client;
  client = new S3Client({
    region: requiredEnv('S3_REGION'),
    endpoint: requiredEnv('S3_ENDPOINT'),
    forcePathStyle: String(process.env.S3_FORCE_PATH_STYLE || 'false').toLowerCase() === 'true',
    credentials: {
      accessKeyId: requiredEnv('S3_ACCESS_KEY'),
      secretAccessKey: requiredEnv('S3_SECRET_KEY'),
    },
  });
  return client;
}

function publicBase(): string {
  return String(process.env.STORAGE_PUBLIC_URL || '').replace(/\/$/, '');
}

function bucketName(): string {
  return requiredEnv('S3_BUCKET');
}

export function generateAvatarFilename(mimeType: string) {
  const ext = allowedMimeToExt[mimeType];
  if (!ext) {
    throw new Error('Unsupported avatar mime type.');
  }
  return `${Date.now()}-${crypto.randomUUID()}${ext}`;
}

/** Uploads an avatar buffer to B2 under avatars/ and returns its object key. */
export async function uploadAvatarBuffer(buffer: Buffer, mimeType: string): Promise<string> {
  if (!isConfigured()) {
    throw new Error('Avatar storage is not configured (S3_ENDPOINT/S3_REGION/S3_BUCKET/S3_ACCESS_KEY/S3_SECRET_KEY).');
  }
  const key = `avatars/${generateAvatarFilename(mimeType)}`;
  await getClient().send(
    new PutObjectCommand({
      Bucket: bucketName(),
      Key: key,
      Body: buffer,
      ContentType: mimeType,
    })
  );
  return key;
}

/** Canonical public URL for a stored avatar object key. */
export function getPublicAvatarUrl(key: string) {
  return `${publicBase()}/${bucketName()}/${key}`;
}

function getAvatarKeyFromUrl(url?: string | null): string | null {
  if (!url) return null;
  const prefix = `${publicBase()}/${bucketName()}/`;
  if (!url.startsWith(prefix)) return null;
  const key = url.slice(prefix.length);
  // avatars/<timestamp>-<uuid>.<ext> — reject anything else defensively.
  if (!/^avatars\/[a-zA-Z0-9._-]+$/.test(key)) return null;
  return key;
}

export async function removeAvatarByUrl(url?: string | null) {
  const key = getAvatarKeyFromUrl(url);
  if (!key) return;
  if (!isConfigured()) return;
  try {
    await getClient().send(new DeleteObjectCommand({ Bucket: bucketName(), Key: key }));
  } catch (error: any) {
    // Object already gone (or never existed) — same "best effort" semantics
    // the previous fs.unlink/ENOENT-tolerant implementation had.
    if (error?.name !== 'NoSuchKey' && error?.$metadata?.httpStatusCode !== 404) throw error;
  }
}
