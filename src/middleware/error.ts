import { Request, Response, NextFunction } from 'express';
import { logger } from '../lib/logger.js';
import { AppError } from '../lib/errors.js';
import multer from 'multer';

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  if (err instanceof AppError) {
    res.status(err.status).json({ success: false, message: err.message, code: err.code });
    return;
  }

  if (err instanceof multer.MulterError) {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'Avatar file size must not exceed 2MB.'
      : 'File upload failed.';
    res.status(400).json({ success: false, message, code: 'UPLOAD_ERROR' });
    return;
  }

  logger.error(err, 'Unhandled error');
  res.status(500).json({ success: false, message: 'Internal Server Error', code: 'INTERNAL_ERROR' });
}
