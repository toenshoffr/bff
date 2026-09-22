import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, RequestHandler, Response } from 'express';
import { config } from '../config.js';

const CSRF_COOKIE = 'bff.csrf';
const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function csrfCookieOptions() {
  return {
    httpOnly: false,
    secure: config.session.cookieSecure,
    sameSite: config.session.cookieSameSite,
    maxAge: config.session.cookieMaxAgeMs,
  };
}

/**
 * Generates a fresh CSRF token, binds it to the session (the source of truth), and
 * mirrors it into the readable cookie the SPA sends back as a header. Callers should
 * invoke this whenever the session identity changes (login, logout) so a token
 * observed before authentication can't be replayed after it.
 */
export function rotateCsrfToken(req: Request, res: Response): string {
  const token = randomBytes(32).toString('hex');
  req.session.csrfToken = token;
  res.cookie(CSRF_COOKIE, token, csrfCookieOptions());
  return token;
}

export function clearCsrfToken(req: Request, res: Response): void {
  delete req.session.csrfToken;
  res.clearCookie(CSRF_COOKIE);
}

/**
 * GET /auth/csrf — issues (or re-issues) the session-bound CSRF token in a readable
 * (non-httpOnly) cookie and echoes it in the body so the SPA can read it and send it
 * back as a header on state-changing requests (double-submit cookie pattern). The
 * token itself lives in server-side session state; the cookie is just a delivery
 * mechanism, so an attacker who can merely set a cookie on this origin can't forge one.
 */
export const issueCsrfToken: RequestHandler = (req, res) => {
  if (req.session.csrfToken) {
    res.cookie(CSRF_COOKIE, req.session.csrfToken, csrfCookieOptions());
  } else {
    rotateCsrfToken(req, res);
  }
  res.set('Cache-Control', 'no-store');
  res.json({ csrfToken: req.session.csrfToken! });
};

function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

/** Rejects state-changing requests whose X-CSRF-Token header doesn't match the session's token. */
export const csrfProtection: RequestHandler = (req, res, next) => {
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }
  const sessionToken = req.session.csrfToken;
  const headerToken = req.get(CSRF_HEADER);
  if (!sessionToken || !headerToken || !timingSafeEqualStr(sessionToken, headerToken)) {
    return res.status(403).json({ error: 'invalid_csrf_token' });
  }
  next();
};
