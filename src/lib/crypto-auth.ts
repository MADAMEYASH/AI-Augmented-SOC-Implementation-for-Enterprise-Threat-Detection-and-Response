import crypto from 'crypto';

/**
 * Enterprise Cryptographic Password & Secret Hashing Service
 * Implements scrypt with a 16-byte random salt, 64-byte key length,
 * and constant-time timingSafeEqual comparison to eliminate timing attacks.
 */

const SCRYPT_KEYLEN = 64;

export interface HashResult {
  hash: string;
  salt: string;
  combined: string; // "scrypt:salt:hash"
}

export interface PasswordValidationResult {
  valid: boolean;
  score: number; // 0 to 100
  errors: string[];
}

/**
 * Validates password entropy and security policy
 */
export function validatePasswordStrength(password: string): PasswordValidationResult {
  const errors: string[] = [];
  let score = 0;

  if (!password || typeof password !== 'string') {
    return { valid: false, score: 0, errors: ['Password is required'] };
  }

  if (password.length >= 12) score += 30;
  else if (password.length >= 8) score += 15;
  else errors.push('Password must be at least 12 characters long');

  if (/[A-Z]/.test(password)) score += 20;
  else errors.push('Password must contain at least one uppercase letter (A-Z)');

  if (/[a-z]/.test(password)) score += 20;
  else errors.push('Password must contain at least one lowercase letter (a-z)');

  if (/[0-9]/.test(password)) score += 15;
  else errors.push('Password must contain at least one number (0-9)');

  if (/[^A-Za-z0-9]/.test(password)) score += 15;
  else errors.push('Password must contain at least one special character (!@#$%^&* etc.)');

  const commonPatterns = ['password', '123456', 'admin', 'qwerty', 'letmein', 'soc123'];
  if (commonPatterns.some(p => password.toLowerCase().includes(p))) {
    score = Math.max(0, score - 40);
    errors.push('Password contains easily guessable dictionary patterns');
  }

  return {
    valid: errors.length === 0,
    score: Math.min(100, score),
    errors,
  };
}

/**
 * Hashes a password or secret using scrypt and a cryptographically secure random salt
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt:${salt}:${derivedKey.toString('hex')}`);
    });
  });
}

/**
 * Verifies a plaintext password against a stored scrypt hash using constant-time comparison
 */
export async function verifyPassword(password: string, combinedHash: string): Promise<boolean> {
  try {
    const parts = combinedHash.split(':');
    if (parts.length !== 3 || parts[0] !== 'scrypt') {
      return false;
    }

    const salt = parts[1];
    const originalHash = parts[2];
    const originalBuffer = Buffer.from(originalHash, 'hex');

    return new Promise((resolve) => {
      crypto.scrypt(password, salt, SCRYPT_KEYLEN, (err, derivedKey) => {
        if (err) return resolve(false);
        // Constant-time comparison to prevent timing attacks
        if (derivedKey.length !== originalBuffer.length) {
          return resolve(false);
        }
        resolve(crypto.timingSafeEqual(derivedKey, originalBuffer));
      });
    });
  } catch {
    return false;
  }
}
