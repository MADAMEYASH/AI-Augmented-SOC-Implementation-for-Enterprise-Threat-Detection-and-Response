import { Request, Response, NextFunction } from 'express';
import { adminAuth } from '../lib/firebase-admin.ts';
import { DecodedIdToken } from 'firebase-admin/auth';
import { getOrCreateUser } from '../db/users.ts';

export interface AuthRequest extends Request {
  user?: DecodedIdToken & { dbRole?: string };
}

export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  // If no auth token provided, check if in development/demo override
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // For demo/standalone mode when no token is passed, allow analyst tier with warning
    if (process.env.ALLOW_ANONYMOUS_SOC === 'true' || !process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
      req.user = {
        uid: 'soc-analyst-local',
        email: 'analyst@corp.internal',
        dbRole: 'admin', // allow full administrative access in dev/demo
      } as any;
      return next();
    }
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid authorization token' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await adminAuth.verifyIdToken(token);
    const dbUser = await getOrCreateUser(
      decodedToken.uid,
      decodedToken.email || 'unknown@domain.internal',
      decodedToken.name
    );
    req.user = {
      ...decodedToken,
      dbRole: dbUser.role,
    };
    next();
  } catch (error) {
    console.error('Error verifying Firebase ID token:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid token verification failed' });
  }
};

export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const role = req.user?.dbRole || 'analyst';
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({
        error: `Forbidden: Operation requires one of roles [${allowedRoles.join(', ')}]. Current role: ${role}`,
      });
    }
    next();
  };
};
