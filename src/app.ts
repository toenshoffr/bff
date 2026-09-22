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

  // Needed so `secure` cookies and req.protocol are correct behind a reverse proxy/load balancer.
  app.set('trust proxy', 1);

  app.use(helmet());
  app.use(cors({ origin: config.frontendOrigin, credentials: true }));
  app.use(express.json());
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

  app.use(csrfProtection);

  app.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

  app.use('/auth', authRouter);
  app.use(config.api.proxyPath, apiProxy);

  app.use(errorHandler);

  return app;
}
