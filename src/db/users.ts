import { db } from './index.ts';
import { users } from './schema.ts';
import { eq } from 'drizzle-orm';

export async function getOrCreateUser(uid: string, email: string, name?: string) {
  try {
    const existing = await db.select().from(users).where(eq(users.uid, uid));
    if (existing.length > 0) {
      await db
        .update(users)
        .set({
          lastLoginAt: new Date(),
          email,
          name: name || existing[0].name,
        })
        .where(eq(users.uid, uid));
      return existing[0];
    }

    // First user or default analyst role
    const countResult = await db.select().from(users);
    const role = countResult.length === 0 ? 'admin' : 'analyst';

    const inserted = await db
      .insert(users)
      .values({
        uid,
        email,
        name: name || email.split('@')[0],
        role,
        lastLoginAt: new Date(),
      })
      .returning();

    return inserted[0];
  } catch (error) {
    console.error('Database user query failed:', error);
    throw new Error('Database operation failed while synchronizing user profile.', { cause: error });
  }
}

export async function getUserRole(uid: string): Promise<string> {
  try {
    const result = await db.select().from(users).where(eq(users.uid, uid));
    return result[0]?.role || 'analyst';
  } catch (error) {
    console.error('Failed to get user role:', error);
    return 'analyst';
  }
}
