import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../');
const avatarDirectory = path.join(projectRoot, 'uploads', 'avatars');
const publicAvatarBasePath = '/uploads/avatars';

const allowedMimeToExt: Record<string, string> = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};

export function getAvatarDirectory() {
  return avatarDirectory;
}

export function getPublicAvatarUrl(filename: string) {
  const apiBase = process.env.API_BASE_URL || 'http://localhost:5010';
  return `${apiBase}${publicAvatarBasePath}/${filename}`;
}

export function getAvatarFilenameFromUrl(url?: string | null) {
  if (!url) return null;
  const pathPart = `${publicAvatarBasePath}/`;
  const index = url.indexOf(pathPart);
  if (index === -1) return null;
  const filename = url.slice(index + pathPart.length);
  if (!/^[a-zA-Z0-9._-]+$/.test(filename)) return null;
  return filename;
}

export async function ensureAvatarDirectory() {
  await fs.mkdir(avatarDirectory, { recursive: true });
}

export function generateAvatarFilename(mimeType: string) {
  const ext = allowedMimeToExt[mimeType];
  if (!ext) {
    throw new Error('Unsupported avatar mime type.');
  }
  return `${Date.now()}-${crypto.randomUUID()}${ext}`;
}

export async function removeAvatarByUrl(url?: string | null) {
  const filename = getAvatarFilenameFromUrl(url);
  if (!filename) return;
  const filePath = path.join(avatarDirectory, filename);
  try {
    await fs.unlink(filePath);
  } catch (error: any) {
    if (error?.code !== 'ENOENT') throw error;
  }
}
