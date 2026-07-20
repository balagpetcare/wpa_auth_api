import multer from 'multer';
import path from 'path';
import { AppError } from '../lib/errors.js';

const allowedMimeTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp']);

// Memory storage: the buffer is uploaded straight to B2 (see
// avatarStorage.ts's uploadAvatarBuffer) — nothing is written to VPS disk.
const storage = multer.memoryStorage();

function fileFilter(_req: Express.Request, file: Express.Multer.File, cb: multer.FileFilterCallback) {
  const ext = path.extname(file.originalname).toLowerCase();
  if (!allowedMimeTypes.has(file.mimetype) || !allowedExtensions.has(ext)) {
    cb(new AppError('Only JPG, PNG, and WEBP images are allowed.', 'VALIDATION_ERROR', 400));
    return;
  }
  cb(null, true);
}

export const avatarUpload = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024,
    files: 1,
  },
  fileFilter,
});
