import type { Response, NextFunction } from 'express';
import type { AuthRequest } from './auth.middleware';

export const requireIssuer = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && (req.user.isIssuer || req.user.isAdmin)) {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Forbidden: Requires Issuer or Admin role' });
  }
};

export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Forbidden: Requires Admin role' });
  }
};
