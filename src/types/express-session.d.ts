import 'express-session';

declare module 'express-session' {
  interface SessionData {
    authMethod?: 'password' | 'oauth';
    tokens?: {
      accessToken: string;
      refreshToken?: string;
      /** epoch milliseconds */
      expiresAt: number;
    };
    user?: Record<string, unknown>;
    csrfToken?: string;
    oauthFlow?: {
      state: string;
      codeVerifier: string;
      redirectTo?: string;
    };
  }
}
