import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, AccessTokenPayload } from '../lib/tokens.js';
import { prisma } from '../lib/db.js';
import { AppError } from '../lib/errors.js';
import { hasAuthenticatableAccount } from '../modules/auth/accountPolicy.js';

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
    prisma.user.findUnique({
      where: { id: payload.sub },
      select: { status: true },
    }).then((user) => {
      if (!hasAuthenticatableAccount(user)) {
        throw new AppError('Account is not active.', 'ACCOUNT_INACTIVE', 403);
      }

      req.user = { ...payload, id: payload.sub };
      next();
    }).catch((error) => {
      if (error instanceof AppError && error.code === 'ACCOUNT_INACTIVE') {
        res.status(403).json({
          success: false,
          message: error.message,
          code: error.code,
        });
        return;
      }

      res.status(401).json({ success: false, message: 'Invalid or expired access token.', code: 'TOKEN_INVALID' });
    });
  } catch {
    res.status(401).json({ success: false, message: 'Invalid or expired access token.', code: 'TOKEN_INVALID' });
  }
}

// Alias kept for any existing consumers
export const authenticate = authGuard;
