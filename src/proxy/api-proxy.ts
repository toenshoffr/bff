import type { RequestHandler } from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { ensureFreshTokens, UnauthenticatedError } from '../auth/token-service.js';
import { config } from '../config.js';

const proxy = createProxyMiddleware({
  target: config.api.baseUrl,
  changeOrigin: true,
  pathRewrite: { [`^${config.api.proxyPath}`]: '' },
  onProxyReq: (proxyReq, req) => {
    const token = (req as unknown as { bffAccessToken?: string }).bffAccessToken;
    if (token) {
      proxyReq.setHeader('Authorization', `Bearer ${token}`);
    }
  },
});

/**
 * Resolves a fresh access token for the caller's session (refreshing if needed),
 * then hands off to the reverse proxy targeting the Spring Boot API. The browser
 * never sees the JWT — it only ever holds the httpOnly session cookie.
 */
export const apiProxy: RequestHandler = async (req, res, next) => {
  try {
    (req as unknown as { bffAccessToken: string }).bffAccessToken = await ensureFreshTokens(req);
  } catch (err) {
    if (err instanceof UnauthenticatedError) {
      res.status(401).json({ error: 'unauthenticated' });
      return;
    }
    next(err);
    return;
  }
  proxy(req, res, next);
};
