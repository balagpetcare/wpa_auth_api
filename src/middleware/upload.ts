import multer from 'multer';
import path from 'path';
import { AppError } from '../lib/errors.js';
import { ensureAvatarDirectory, generateAvatarFilename, getAvatarDirectory } from '../lib/avatarStorage.js';

const allowedMimeTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const allowedExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp']);

const storage = multer.diskStorage({
  destination: async (_req, _file, cb) => {
    try {
      await ensureAvatarDirectory();
      cb(null, getAvatarDirectory());
    } catch (error) {
      cb(error as Error, '');
    }
  },
  filename: (_req, file, cb) => {
    try {
      cb(null, generateAvatarFilename(file.mimetype));
    } catch (error) {
      cb(error as Error, '');
    }
  },
});

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
