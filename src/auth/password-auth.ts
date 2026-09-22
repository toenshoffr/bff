import axios from 'axios';
import { Router } from 'express';
import { config } from '../config.js';
import { rotateCsrfToken } from '../middleware/csrf.js';
import { loginRateLimiter } from '../middleware/rate-limit.js';
import { normalizePasswordTokenResponse } from './token-service.js';

export const passwordAuthRouter = Router();

passwordAuthRouter.post('/login', loginRateLimiter, async (req, res, next) => {
  const { username, password } = req.body ?? {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  try {
    const { data } = await axios.post(
      `${config.api.baseUrl}${config.password.loginPath}`,
      { username, password },
      { timeout: config.api.timeoutMs },
    );
    const tokens = normalizePasswordTokenResponse(data);

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.authMethod = 'password';
      req.session.tokens = tokens;
      req.session.user = data.user ?? { username };
      // The pre-login CSRF token (if any) belonged to an anonymous session that no
      // longer exists after regenerate(); issue a fresh one bound to the new session.
      rotateCsrfToken(req, res);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.json({ authenticated: true, user: req.session.user });
      });
    });
  } catch (err: any) {
    if (axios.isAxiosError(err) && (err.response?.status === 401 || err.response?.status === 400)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    next(err);
  }
});
