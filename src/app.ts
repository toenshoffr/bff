import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import { config } from './config.js';
import { csrfProtection } from './middleware/csrf.js';
import { errorHandler } from './middleware/error-handler.js';
import { apiProxy } from './proxy/api-proxy.js';
import { authRouter } from './routes/auth.js';

export function createApp() {
  const app = express();

  // Only trust X-Forwarded-* from as many hops as are actually configured in front
  // of this app (see TRUST_PROXY in config.ts). Defaults to trusting none, since a
  // BFF reachable directly would otherwise let a client spoof
  // X-Forwarded-Proto/-For and fool `secure` cookies / req.protocol / req.ip.
  app.set('trust proxy', config.trustProxy);

  app.use(helmet());
  app.use(cors({ origin: config.frontendOrigin, credentials: true }));
  app.use(cookieParser());

  app.use(
    session({
      name: config.session.cookieName,
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: config.session.cookieSecure,
        sameSite: config.session.cookieSameSite,
        maxAge: config.session.cookieMaxAgeMs,
      },
      // Default MemoryStore is fine for local dev only. For production, plug in a
      // shared store (e.g. connect-redis) so sessions survive restarts and work
      // across multiple BFF instances.
    }),
  );

  if (config.session.csrfProtectionEnabled) {
    app.use(csrfProtection);
  } else {
    console.warn('CSRF_PROTECTION_ENABLED=false — CSRF protection is DISABLED. Testing only, never in production.');
  }

  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

  // JSON body parsing is scoped to /auth only, not applied globally: /api/** is a
  // raw reverse proxy, and consuming/re-encoding the body here would either hang
  // proxied JSON requests (http-proxy-middleware can't re-stream an already-read
  // body) or require re-serializing it, which breaks non-JSON payloads. Letting the
  // proxy see the untouched request stream sidesteps both.
  app.use('/auth', express.json());
  app.use('/auth', authRouter);
  app.use(config.api.proxyPath, apiProxy);

  app.use(errorHandler);

  return app;
}
