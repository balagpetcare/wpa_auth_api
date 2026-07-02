import { Request, Response, NextFunction } from 'express';
import { logger } from '../lib/logger.js';
import { AppError } from '../lib/errors.js';
import multer from 'multer';

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  if (err instanceof AppError) {
    res.status(err.status).json({
      success: false,
      message: err.message,
      code: err.code,
      requestId: req.requestId,
    });
    return;
  }

  if (err instanceof multer.MulterError) {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'Avatar file size must not exceed 2MB.'
      : 'File upload failed.';
    res.status(400).json({ success: false, message, code: 'UPLOAD_ERROR', requestId: req.requestId });
    return;
  }

  logger.error({ err, requestId: req.requestId, path: req.originalUrl, method: req.method }, 'Unhandled error');
  res.status(500).json({ success: false, message: 'Internal Server Error', code: 'INTERNAL_ERROR', requestId: req.requestId });
}
