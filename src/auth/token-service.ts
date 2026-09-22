import axios from 'axios';
import type { Request } from 'express';
import { config } from '../config.js';

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

/**
 * Returns a currently-valid access token for the request's session, transparently
 * refreshing it (via the same auth method the session was established with) when
 * it is expired or about to expire. Throws UnauthenticatedError if there is no
 * usable session.
 */
export async function ensureFreshTokens(req: Request): Promise<string> {
  const tokens = req.session.tokens;
  if (!tokens) {
    throw new UnauthenticatedError();
  }

  if (Date.now() < tokens.expiresAt - REFRESH_SKEW_MS) {
    return tokens.accessToken;
  }

  if (!tokens.refreshToken) {
    throw new UnauthenticatedError('Session expired');
  }

  const refreshed =
    req.session.authMethod === 'oauth'
      ? await refreshOAuthTokens(tokens.refreshToken)
      : await refreshPasswordTokens(tokens.refreshToken);

  req.session.tokens = refreshed;
  return refreshed.accessToken;
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
