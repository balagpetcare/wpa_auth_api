import { randomUUID } from 'crypto';
import { Request, Response, NextFunction } from 'express';

export const REQUEST_ID_HEADER = 'x-request-id';

declare global {
  namespace Express {
    interface Request {
      requestId?: string;
      requestStartAt?: number;
    }
  }
}

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction) {
  const headerValue = req.header(REQUEST_ID_HEADER);
  const requestId = headerValue && headerValue.trim() ? headerValue.trim() : randomUUID();
  req.requestId = requestId;
  req.requestStartAt = Date.now();
  res.setHeader('X-Request-ID', requestId);
  next();
}
