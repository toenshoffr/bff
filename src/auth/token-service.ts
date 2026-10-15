import axios from 'axios';
import type { Request } from 'express';
import type { SessionData } from 'express-session';
import { config } from '../config.js';
import { refreshLock, sessionStore } from '../session/session-backend.js';

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  /** epoch milliseconds */
  expiresAt: number;
}

export class UnauthenticatedError extends Error {
  constructor(message = 'No active session') {
    super(message);
    this.name = 'UnauthenticatedError';
  }
}

const REFRESH_SKEW_MS = 10_000;

/** Extracts a normalized token set from the Spring Boot username/password login/refresh response. */
export function normalizePasswordTokenResponse(data: any): TokenSet {
  const accessToken = data?.accessToken ?? data?.access_token;
  if (!accessToken) {
    throw new Error('Backend auth response did not include an access token');
  }
  const expiresInSec = data?.expiresIn ?? data?.expires_in ?? 300;
  return {
    accessToken,
    refreshToken: data?.refreshToken ?? data?.refresh_token,
    expiresAt: Date.now() + expiresInSec * 1000,
  };
}

/** Extracts a normalized token set from an OAuth token endpoint response. */
export function normalizeOAuthTokenResponse(data: any, previousRefreshToken?: string): TokenSet {
  const accessToken = data?.access_token;
  if (!accessToken) {
    throw new Error('OAuth token endpoint response did not include an access_token');
  }
  const expiresInSec = data?.expires_in ?? 300;
  return {
    accessToken,
    refreshToken: data?.refresh_token ?? previousRefreshToken,
    expiresAt: Date.now() + expiresInSec * 1000,
  };
}

const isFresh = (tokens: TokenSet) => Date.now() < tokens.expiresAt - REFRESH_SKEW_MS;

/**
 * Returns a currently-valid access token for the request's session, transparently
 * refreshing it (via the same auth method the session was established with) when
 * it is expired or about to expire. Throws UnauthenticatedError if there is no
 * usable session.
 *
 * Refreshes are serialized per session (and across BFF instances when Redis is the
 * session store). SPAs fire parallel requests, and with refresh-token rotation a
 * second refresh using the already-consumed token would be rejected and log the user
 * out. Inside the lock the session is re-read from the store, so a request that
 * waited simply picks up the tokens its predecessor just persisted.
 */
export async function ensureFreshTokens(req: Request): Promise<string> {
  const tokens = req.session.tokens;
  if (!tokens) {
    throw new UnauthenticatedError();
  }
  if (isFresh(tokens)) {
    return tokens.accessToken;
  }

  return refreshLock.run(req.sessionID, async () => {
    const stored = await loadStoredSession(req.sessionID);
    // Gone (e.g. logout while we waited) or logged out: never resurrect the session.
    if (!stored?.tokens) {
      throw new UnauthenticatedError();
    }
    if (isFresh(stored.tokens)) {
      req.session.tokens = stored.tokens;
      return stored.tokens.accessToken;
    }
    if (!stored.tokens.refreshToken) {
      throw new UnauthenticatedError('Session expired');
    }

    const refreshed =
      stored.authMethod === 'oauth'
        ? await refreshOAuthTokens(stored.tokens.refreshToken)
        : await refreshPasswordTokens(stored.tokens.refreshToken);

    // Persist immediately rather than at response end: requests that start while this
    // one is still streaming its response must already see the rotated refresh token.
    req.session.tokens = refreshed;
    await new Promise<void>((resolve, reject) => req.session.save((err) => (err ? reject(err) : resolve())));
    return refreshed.accessToken;
  });
}

function loadStoredSession(sid: string): Promise<SessionData | null> {
  return new Promise((resolve, reject) => {
    sessionStore.get(sid, (err, data) => (err ? reject(err) : resolve(data ?? null)));
  });
}

async function refreshPasswordTokens(refreshToken: string): Promise<TokenSet> {
  try {
    const { data } = await axios.post(
      `${config.api.baseUrl}${config.password.refreshPath}`,
      { refreshToken },
      { timeout: config.api.timeoutMs },
    );
    return normalizePasswordTokenResponse(data);
  } catch {
    throw new UnauthenticatedError('Session expired');
  }
}

async function refreshOAuthTokens(refreshToken: string): Promise<TokenSet> {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: config.oauth.clientId!,
  });
  if (config.oauth.clientSecret) {
    body.set('client_secret', config.oauth.clientSecret);
  }
  try {
    const { data } = await axios.post(config.oauth.tokenEndpoint!, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: config.api.timeoutMs,
    });
    return normalizeOAuthTokenResponse(data, refreshToken);
  } catch {
    throw new UnauthenticatedError('Session expired');
  }
}
