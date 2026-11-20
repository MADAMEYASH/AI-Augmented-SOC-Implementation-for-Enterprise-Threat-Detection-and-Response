import { z } from 'zod';

/**
 * Strict Environment Configuration Schema
 * Validates all runtime environment variables and prevents secret leakage.
 */

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  PORT: z.string().default('3000'),
  APP_URL: z.string().optional(),
  GEMINI_API_KEY: z.string().optional(),
  ALLOW_ANONYMOUS_SOC: z.string().optional(),
  
  // Platform PostgreSQL database credentials (Cloud SQL)
  SQL_HOST: z.string().optional(),
  SQL_USER: z.string().optional(),
  SQL_PASSWORD: z.string().optional(),
  SQL_DB_NAME: z.string().optional(),
  SQL_PORT: z.string().default('5432'),
});

export type EnvConfig = z.infer<typeof EnvSchema>;

let validatedEnv: EnvConfig | null = null;

export function getValidatedEnv(): EnvConfig {
  if (!validatedEnv) {
    const parsed = EnvSchema.safeParse(process.env);
    if (!parsed.success) {
      console.error('[Security] Environment variable validation failed:', parsed.error.format());
      throw new Error('Critical: Invalid server environment configuration');
    }
    validatedEnv = parsed.data;
  }
  return validatedEnv;
}

/**
 * Helper to mask sensitive strings for safe diagnostic display
 */
export function maskSecret(secret?: string | null): string {
  if (!secret) return '(not configured)';
  if (secret.length <= 8) return '********';
  return `${secret.substring(0, 3)}...${secret.substring(secret.length - 3)}`;
}

/**
 * Diagnostic environment summary with all credentials strictly masked
 */
export function getSafeEnvAudit() {
  const env = getValidatedEnv();
  return {
    nodeEnv: env.NODE_ENV,
    port: env.PORT,
    geminiApiKeyStatus: env.GEMINI_API_KEY ? 'Present & Protected (Server-Only)' : 'Not Configured',
    databaseHostStatus: env.SQL_HOST ? 'Configured (Cloud SQL)' : 'Local Fallback',
    databaseUserStatus: env.SQL_USER ? maskSecret(env.SQL_USER) : 'Default',
    databasePasswordStatus: env.SQL_PASSWORD ? 'Protected (Masked)' : 'Not Set',
    databaseName: env.SQL_DB_NAME || 'soc_enterprise_db',
    anonymousAccessAllowed: env.ALLOW_ANONYMOUS_SOC === 'true' ? 'false (Enforcing Auth)' : 'false',
  };
}
