import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, AccessTokenPayload } from '../lib/tokens.js';

export interface AuthenticatedRequest extends Request {
  user?: AccessTokenPayload & { id: string };
}

export function authGuard(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ success: false, message: 'Missing or malformed Authorization header.', code: 'UNAUTHORIZED' });
    return;
  }

  const token = authHeader.slice(7);
  try {
    const payload = verifyAccessToken(token);
    req.user = { ...payload, id: payload.sub };
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired access token.', code: 'TOKEN_INVALID' });
  }
}

// Alias kept for any existing consumers
export const authenticate = authGuard;
