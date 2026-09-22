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

    SESSION_SECRET: z.string().min(16, 'SESSION_SECRET must be at least 16 characters'),
    COOKIE_NAME: z.string().default('bff.sid'),
    COOKIE_SECURE: boolFromEnv(true),
    COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),
    COOKIE_MAX_AGE_MS: z.coerce.number().default(1000 * 60 * 60 * 8),

    // Testing escape hatch only — never disable in production.
    CSRF_PROTECTION_ENABLED: boolFromEnv(true),

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

export const config = {
  port: parsed.PORT,
  nodeEnv: parsed.NODE_ENV,
  isProduction: parsed.NODE_ENV === 'production',
  frontendOrigin: parsed.FRONTEND_ORIGIN,
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
