import { Router } from 'express';
import { oauthAuthRouter } from '../auth/oauth-auth.js';
import { passwordAuthRouter } from '../auth/password-auth.js';
import { config } from '../config.js';
import { issueCsrfToken } from '../middleware/csrf.js';

export const authRouter = Router();

authRouter.get('/csrf', issueCsrfToken);

authRouter.get('/status', (req, res) => {
  if (!req.session.tokens) {
    return res.json({ authenticated: false });
  }
  res.json({
    authenticated: true,
    authMethod: req.session.authMethod,
    user: req.session.user ?? null,
  });
});

authRouter.post('/logout', (req, res, next) => {
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
