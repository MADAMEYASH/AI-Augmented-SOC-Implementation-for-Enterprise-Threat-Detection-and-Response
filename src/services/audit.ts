import { db } from '../db/index.ts';
import { auditLogs } from '../db/schema.ts';

export interface AuditLogEntry {
  userId?: string;
  userEmail?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  details?: Record<string, any>;
  ipAddress?: string;
}

export async function logAuditEvent(entry: AuditLogEntry): Promise<void> {
  try {
    await db.insert(auditLogs).values({
      userId: entry.userId || 'system',
      userEmail: entry.userEmail || 'system@soc.internal',
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId || null,
      details: entry.details || null,
      ipAddress: entry.ipAddress || '127.0.0.1',
    });
  } catch (error) {
    console.error('Failed to write audit log to PostgreSQL:', error);
  }
}
