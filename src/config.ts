import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const boolFromEnv = (def: boolean) =>
  z
    .preprocess((v) => (typeof v === 'string' ? v.toLowerCase() === 'true' : v), z.boolean())
    .default(def);

const authMethodsSchema = z
  .preprocess(
    (v) => (typeof v === 'string' ? v.split(',').map((s) => s.trim()).filter(Boolean) : v),
    z.array(z.enum(['password', 'oauth'])).min(1),
  )
  .default(['password']);

const envSchema = z
  .object({
    PORT: z.coerce.number().default(3000),
    NODE_ENV: z.string().default('development'),

    FRONTEND_ORIGIN: z.string().url(),

    API_BASE_URL: z.string().url(),
    API_TIMEOUT_MS: z.coerce.number().default(10000),
    API_PROXY_PATH: z.string().default('/api'),

    AUTH_METHODS: authMethodsSchema,

    // Value passed to Express's `trust proxy` setting: how many hops of
    // X-Forwarded-* headers to trust from the edge inward. "false"/"0" (the default)
    // trusts none, which is safest when the BFF might ever be reached directly —
    // otherwise a client can spoof X-Forwarded-Proto/-For. Set to the number of
    // reverse proxies actually in front of the BFF (usually "1"), or a keyword
    // Express understands ("loopback", "linklocal", "uniquelocal"), or a specific
    // IP/CIDR.
    TRUST_PROXY: z.string().default('false'),

    SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
    COOKIE_NAME: z.string().default('bff.sid'),
    COOKIE_SECURE: boolFromEnv(true),
    COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),
    COOKIE_MAX_AGE_MS: z.coerce.number().default(1000 * 60 * 60 * 8),

    // Where session data (incl. access/refresh tokens) is stored server-side.
    // "memory" is single-instance and lost on restart: local dev only.
    SESSION_STORE: z.enum(['memory', 'redis']).default('memory'),
    REDIS_URL: z.string().optional(),
    REDIS_KEY_PREFIX: z.string().default('bff:sess:'),
    // Encrypts session data (AES-256-GCM) before it is written to the store, so
    // tokens aren't readable by anyone with access to Redis / its backups.
    SESSION_ENCRYPTION_ENABLED: boolFromEnv(true),
    // Dedicated key material (>= 32 chars, e.g. `openssl rand -base64 48`). Must differ
    // from SESSION_SECRET. Optional for the memory store (derived from SESSION_SECRET),
    // required for redis.
    SESSION_ENCRYPTION_KEY: z.string().min(32, 'SESSION_ENCRYPTION_KEY must be at least 32 characters').optional(),

    // Testing escape hatch only — refused at startup when NODE_ENV=production.
    CSRF_PROTECTION_ENABLED: boolFromEnv(true),

    // POST /auth/login throttling (per IP + attempted username).
    RATE_LIMIT_LOGIN_MAX: z.coerce.number().default(10),
    RATE_LIMIT_LOGIN_WINDOW_MS: z.coerce.number().default(60_000),

    PASSWORD_LOGIN_PATH: z.string().default('/api/auth/login'),
    PASSWORD_REFRESH_PATH: z.string().default('/api/auth/refresh'),

    OAUTH_AUTHORIZATION_ENDPOINT: z.string().optional(),
    OAUTH_TOKEN_ENDPOINT: z.string().optional(),
    OAUTH_END_SESSION_ENDPOINT: z.string().optional(),
    OAUTH_CLIENT_ID: z.string().optional(),
    OAUTH_CLIENT_SECRET: z.string().optional(),
    OAUTH_REDIRECT_URI: z.string().optional(),
    OAUTH_SCOPES: z.string().default('openid profile email'),
    OAUTH_POST_LOGIN_REDIRECT: z.string().default('/'),
  })
  .superRefine((val, ctx) => {
    if (val.AUTH_METHODS.includes('oauth')) {
      const required = [
        'OAUTH_AUTHORIZATION_ENDPOINT',
        'OAUTH_TOKEN_ENDPOINT',
        'OAUTH_CLIENT_ID',
        'OAUTH_REDIRECT_URI',
      ] as const;
      for (const key of required) {
        if (!val[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `${key} is required when AUTH_METHODS includes "oauth"`,
            path: [key],
          });
        }
      }
    }

    if (val.NODE_ENV === 'production' && !val.CSRF_PROTECTION_ENABLED) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'CSRF_PROTECTION_ENABLED must not be false when NODE_ENV=production',
        path: ['CSRF_PROTECTION_ENABLED'],
      });
    }

    if (val.SESSION_STORE === 'redis' && !val.REDIS_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'REDIS_URL is required when SESSION_STORE=redis',
        path: ['REDIS_URL'],
      });
    }

    if (val.SESSION_ENCRYPTION_ENABLED) {
      if (val.SESSION_STORE === 'redis' && !val.SESSION_ENCRYPTION_KEY) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'SESSION_ENCRYPTION_KEY is required when SESSION_STORE=redis and encryption is enabled',
          path: ['SESSION_ENCRYPTION_KEY'],
        });
      }
      if (val.SESSION_ENCRYPTION_KEY && val.SESSION_ENCRYPTION_KEY === val.SESSION_SECRET) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'SESSION_ENCRYPTION_KEY must differ from SESSION_SECRET',
          path: ['SESSION_ENCRYPTION_KEY'],
        });
      }
    }

    if (val.COOKIE_SAME_SITE === 'none' && !val.COOKIE_SECURE) {
      // Browsers reject SameSite=None cookies that aren't also Secure, so this
      // combination silently breaks sessions rather than merely weakening them —
      // reject it outright instead of inviting someone to "fix" it by disabling
      // COOKIE_SECURE.
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'COOKIE_SECURE must be true when COOKIE_SAME_SITE=none',
        path: ['COOKIE_SECURE'],
      });
    }
  });

type Env = z.infer<typeof envSchema>;

let parsed: Env;
try {
  parsed = envSchema.parse(process.env);
} catch (err) {
  console.error('Invalid BFF configuration:');
  if (err instanceof z.ZodError) {
    for (const issue of err.issues) {
      console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
    }
  } else {
    console.error(err);
  }
  process.exit(1);
}

function parseTrustProxy(value: string): boolean | number | string {
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

export const config = {
  port: parsed.PORT,
  nodeEnv: parsed.NODE_ENV,
  isProduction: parsed.NODE_ENV === 'production',
  frontendOrigin: parsed.FRONTEND_ORIGIN,
  trustProxy: parseTrustProxy(parsed.TRUST_PROXY),
  api: {
    baseUrl: parsed.API_BASE_URL,
    timeoutMs: parsed.API_TIMEOUT_MS,
    proxyPath: parsed.API_PROXY_PATH,
  },
  authMethods: parsed.AUTH_METHODS,
  session: {
    secret: parsed.SESSION_SECRET,
    cookieName: parsed.COOKIE_NAME,
    cookieSecure: parsed.COOKIE_SECURE,
    cookieSameSite: parsed.COOKIE_SAME_SITE,
    cookieMaxAgeMs: parsed.COOKIE_MAX_AGE_MS,
    csrfProtectionEnabled: parsed.CSRF_PROTECTION_ENABLED,
    store: parsed.SESSION_STORE,
    redisUrl: parsed.REDIS_URL,
    redisKeyPrefix: parsed.REDIS_KEY_PREFIX,
    encryptionEnabled: parsed.SESSION_ENCRYPTION_ENABLED,
    // Falls back to the cookie secret only for the memory store (see schema above);
    // the HKDF "info" label in encrypted-store.ts keeps the derived key distinct.
    encryptionKey: parsed.SESSION_ENCRYPTION_KEY ?? parsed.SESSION_SECRET,
  },
  rateLimit: {
    loginMax: parsed.RATE_LIMIT_LOGIN_MAX,
    loginWindowMs: parsed.RATE_LIMIT_LOGIN_WINDOW_MS,
  },
  password: {
    loginPath: parsed.PASSWORD_LOGIN_PATH,
    refreshPath: parsed.PASSWORD_REFRESH_PATH,
  },
  oauth: {
    authorizationEndpoint: parsed.OAUTH_AUTHORIZATION_ENDPOINT,
    tokenEndpoint: parsed.OAUTH_TOKEN_ENDPOINT,
    endSessionEndpoint: parsed.OAUTH_END_SESSION_ENDPOINT,
    clientId: parsed.OAUTH_CLIENT_ID,
    clientSecret: parsed.OAUTH_CLIENT_SECRET,
    redirectUri: parsed.OAUTH_REDIRECT_URI,
    scopes: parsed.OAUTH_SCOPES,
    postLoginRedirect: parsed.OAUTH_POST_LOGIN_REDIRECT,
  },
} as const;
