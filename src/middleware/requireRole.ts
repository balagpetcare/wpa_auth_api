import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth.js';
import { AppError } from '../lib/errors.js';

// Case-insensitive comparison so role names from seed (SUPER_ADMIN) and
// code constants (super_admin) both match.
export function requireRole(...roles: string[]) {
  return (req: AuthenticatedRequest, _res: Response, next: NextFunction) => {
    const userRoles = (req.user?.roles ?? []).map((r) => r.toLowerCase());
    const hasRole = roles.some((r) => userRoles.includes(r.toLowerCase()));
    if (!hasRole) {
      return next(new AppError('Forbidden: insufficient role.', 'FORBIDDEN', 403));
    }
    next();
  };
}

export const requireAdmin = requireRole('admin', 'super_admin');
export const requireSuperAdmin = requireRole('super_admin');
