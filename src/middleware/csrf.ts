import { randomBytes } from 'node:crypto';
import type { RequestHandler } from 'express';
import { config } from '../config.js';

const CSRF_COOKIE = 'bff.csrf';
const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * GET /auth/csrf — issues (or re-issues) a random token in a readable (non-httpOnly)
 * cookie and echoes it in the body so the SPA can read it and send it back as a
 * header on state-changing requests (double-submit cookie pattern).
 */
export const issueCsrfToken: RequestHandler = (req, res) => {
  const token = req.cookies?.[CSRF_COOKIE] ?? randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: config.session.cookieSecure,
    sameSite: config.session.cookieSameSite,
    maxAge: config.session.cookieMaxAgeMs,
  });
  res.json({ csrfToken: token });
};

/** Rejects state-changing requests whose X-CSRF-Token header doesn't match the cookie. */
export const csrfProtection: RequestHandler = (req, res, next) => {
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const headerToken = req.get(CSRF_HEADER);
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'invalid_csrf_token' });
  }
  next();
};
