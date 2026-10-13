import type { Response, NextFunction } from 'express';
import type { AuthRequest } from './auth.middleware';

export const requireIssuer = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === 'ISSUER') {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Forbidden: Requires ISSUER role' });
  }
};

export const requireCitizen = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user && req.user.role === 'CITIZEN') {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Forbidden: Requires CITIZEN role' });
  }
};
