import { Request, Response, NextFunction } from 'express';
import xss from 'xss';

/**
 * Enterprise XSS Sanitization Middleware
 * Recursively inspects and sanitizes all string inputs across
 * req.body, req.query, and req.params, neutralizing cross-site scripting
 * vectors, malicious scripts, javascript: pseudo-protocols, and inline events.
 */

// Custom XSS filter options allowing clean text without executing script payload
const xssOptions: Parameters<typeof xss>[1] = {
  whiteList: {}, // Strip all HTML tags
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'xml', 'iframe', 'object'],
  css: false,
};

function sanitizeValue(value: any): any {
  if (typeof value === 'string') {
    // 1. Strip null bytes
    let clean = value.replace(/\0/g, '');
    // 2. Filter XSS
    clean = xss(clean, xssOptions);
    // 3. Remove javascript: pseudo-protocol strings if disguised
    clean = clean.replace(/javascript\s*:/gi, '');
    return clean;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }
  if (value !== null && typeof value === 'object') {
    const sanitizedObj: Record<string, any> = {};
    for (const key of Object.keys(value)) {
      // Disallow prototype pollution keys
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      sanitizedObj[key] = sanitizeValue(value[key]);
    }
    return sanitizedObj;
  }
  return value;
}

export function sanitizeInputs(req: Request, _res: Response, next: NextFunction) {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeValue(req.body);
  }
  if (req.query && typeof req.query === 'object') {
    req.query = sanitizeValue(req.query) as any;
  }
  if (req.params && typeof req.params === 'object') {
    req.params = sanitizeValue(req.params) as any;
  }
  next();
}
