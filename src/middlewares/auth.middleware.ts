import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-for-dev';

export interface UserPayload {
  id?: string;
  address: string;
  role: 'ISSUER' | 'CITIZEN';
  [key: string]: any;
}

export interface AuthRequest extends Request {
  user?: UserPayload;
}

export const authenticateJWT = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ success: false, message: 'Forbidden: Invalid or expired token' });
      }

      req.user = decoded as UserPayload;
      next();
    });
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized: No Bearer token provided' });
  }
};
