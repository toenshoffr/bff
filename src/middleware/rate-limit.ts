import rateLimit from 'express-rate-limit';
import { config } from '../config.js';

/**
 * Throttles POST /auth/login. The BFF is the internet-facing surface for
 * credentials — without this, nothing stops an unauthenticated brute-force sweep
 * against the upstream Spring Boot login endpoint. Keyed on IP + attempted
 * username so one abusive client can't exhaust the budget for every other user
 * sharing that IP (e.g. behind NAT/a corporate proxy).
 */
export const loginRateLimiter = rateLimit({
  windowMs: config.rateLimit.loginWindowMs,
  limit: config.rateLimit.loginMax,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const username = typeof req.body?.username === 'string' ? req.body.username.toLowerCase() : '';
    return `${req.ip}:${username}`;
  },
  message: { error: 'too_many_requests' },
});
