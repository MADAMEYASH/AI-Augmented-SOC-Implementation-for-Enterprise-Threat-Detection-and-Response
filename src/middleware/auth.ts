import { Request, Response, NextFunction } from 'express';
import { adminAuth } from '../lib/firebase-admin.ts';
import { DecodedIdToken } from 'firebase-admin/auth';
import { getOrCreateUser } from '../db/users.ts';

export interface AuthRequest extends Request {
  user?: DecodedIdToken & { dbRole?: string };
}

/**
 * Authentication Middleware:
 * Validates Firebase Bearer tokens strictly and attaches user identity + verified database role.
 */
export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // If anonymous access is strictly enabled for preview/demo, grant only limited read-only 'auditor' role
    // NEVER grant 'admin' to unauthenticated callers!
    if (process.env.ALLOW_ANONYMOUS_SOC === 'true') {
      req.user = {
        uid: 'soc-anonymous-session',
        email: 'anonymous-auditor@corp.internal',
        dbRole: 'auditor', // strictly read-only auditor, never admin
      } as any;
      return next();
    }
    return res.status(401).json({
      error: 'Unauthorized: Authentication required. Missing or malformed Bearer token.',
      code: 'AUTH_REQUIRED',
    });
  }

  const token = authHeader.split('Bearer ')[1]?.trim();
  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized: Empty token provided.',
      code: 'INVALID_TOKEN',
    });
  }

  try {
    const decodedToken = await adminAuth.verifyIdToken(token);
    const dbUser = await getOrCreateUser(
      decodedToken.uid,
      decodedToken.email || 'unknown@domain.internal',
      decodedToken.name
    );
    req.user = {
      ...decodedToken,
      dbRole: dbUser.role, // role stored in PostgreSQL
    };
    next();
  } catch (error: any) {
    return res.status(401).json({
      error: 'Unauthorized: Token verification failed or session expired.',
      code: 'TOKEN_VERIFICATION_FAILED',
    });
  }
};

/**
 * Role-Based Access Control (RBAC) Guard:
 * Strictly blocks users who lack the required role.
 */
export const requireRole = (allowedRoles: string[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Unauthorized: Authentication required for this operation.',
        code: 'AUTH_REQUIRED',
      });
    }

    const role = req.user.dbRole || 'auditor';
    if (!allowedRoles.includes(role)) {
      return res.status(403).json({
        error: `Forbidden: Access restricted. Requires one of [${allowedRoles.join(', ')}]. Current role: ${role}`,
        code: 'INSUFFICIENT_PERMISSIONS',
        requiredRoles: allowedRoles,
        userRole: role,
      });
    }

    next();
  };
};
