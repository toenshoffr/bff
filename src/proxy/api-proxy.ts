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
    // The BFF session/CSRF cookies are this app's own auth mechanism and must never
    // reach the upstream API — it authenticates the caller solely via the bearer
    // token above. Forwarding them would let anything that can read upstream
    // logs/requests replay the caller's BFF session.
    proxyReq.removeHeader('cookie');
  },
  // The browser only ever talks to the BFF, never directly to the upstream API, so
  // CORS and cookies are decided solely by our own middleware. Strip any CORS or
  // Set-Cookie headers the upstream sends back — otherwise they either overwrite
  // (not merge with) the ones the BFF already set (e.g. an upstream
  // `Access-Control-Allow-Origin: *` breaks credentialed requests from the
  // frontend), or, for Set-Cookie, could clobber the BFF's own session/CSRF cookies
  // on the browser.
  onProxyRes: (proxyRes) => {
    for (const header of Object.keys(proxyRes.headers)) {
      if (header.toLowerCase().startsWith('access-control-')) {
        delete proxyRes.headers[header];
      }
    }
    delete proxyRes.headers['set-cookie'];
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
