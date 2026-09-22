import { Router } from 'express';
import { oauthAuthRouter } from '../auth/oauth-auth.js';
import { passwordAuthRouter } from '../auth/password-auth.js';
import { config } from '../config.js';
import { clearCsrfToken, issueCsrfToken } from '../middleware/csrf.js';

export const authRouter = Router();

authRouter.get('/csrf', issueCsrfToken);

// Public, unauthenticated: lets the frontend discover which login flows to render
// (e.g. a username/password form vs. an "Sign in with SSO" button) without hardcoding
// AUTH_METHODS on the client.
authRouter.get('/methods', (_req, res) => {
  const methods: Array<{ type: 'password' | 'oauth'; loginUrl?: string }> = [];
  if (config.authMethods.includes('password')) {
    methods.push({ type: 'password' });
  }
  if (config.authMethods.includes('oauth')) {
    methods.push({ type: 'oauth', loginUrl: '/auth/oauth/login' });
  }
  res.json({ methods });
});

authRouter.get('/status', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const tokens = req.session.tokens;
  // "Authenticated" means the session can still get a usable access token, either
  // because the current one hasn't expired or because it can be refreshed — mirrors
  // ensureFreshTokens' notion of a usable session, not just raw token presence.
  const hasUsableSession = !!tokens && (Date.now() < tokens.expiresAt || !!tokens.refreshToken);
  if (!hasUsableSession) {
    return res.json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    authMethod: req.session.authMethod,
    user: req.session.user ?? null,
  });
});

authRouter.post('/logout', (req, res, next) => {
  clearCsrfToken(req, res);
  req.session.destroy((err) => {
    res.clearCookie(config.session.cookieName);
    if (err) return next(err);
    res.json({ authenticated: false });
  });
});

if (config.authMethods.includes('password')) {
  authRouter.use('/', passwordAuthRouter);
}

if (config.authMethods.includes('oauth')) {
  authRouter.use('/oauth', oauthAuthRouter);
}
