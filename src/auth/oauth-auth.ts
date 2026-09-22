import { createHash, randomBytes } from 'node:crypto';
import axios from 'axios';
import { Router } from 'express';
import { config } from '../config.js';
import { normalizeOAuthTokenResponse } from './token-service.js';

export const oauthAuthRouter = Router();

function base64url(input: Buffer): string {
  return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Starts the Authorization Code + PKCE flow. The confidential client secret is used
 * on the token exchange below; PKCE is added on top as defense in depth.
 */
oauthAuthRouter.get('/login', (req, res) => {
  const state = base64url(randomBytes(16));
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash('sha256').update(codeVerifier).digest());
  const redirectTo = typeof req.query.redirectTo === 'string' ? req.query.redirectTo : undefined;

  req.session.oauthFlow = { state, codeVerifier, redirectTo };

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.oauth.clientId!,
    redirect_uri: config.oauth.redirectUri!,
    scope: config.oauth.scopes,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  req.session.save((err) => {
    if (err) {
      res.status(500).json({ error: 'session_error' });
      return;
    }
    res.redirect(`${config.oauth.authorizationEndpoint}?${params.toString()}`);
  });
});

oauthAuthRouter.get('/callback', async (req, res, next) => {
  const { code, state, error } = req.query;
  const flow = req.session.oauthFlow;

  if (error) {
    return res.redirect(`${config.oauth.postLoginRedirect}?authError=${encodeURIComponent(String(error))}`);
  }
  if (!flow || typeof state !== 'string' || state !== flow.state || typeof code !== 'string') {
    return res.status(400).json({ error: 'invalid_oauth_state' });
  }

  try {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: config.oauth.redirectUri!,
      client_id: config.oauth.clientId!,
      code_verifier: flow.codeVerifier,
    });
    if (config.oauth.clientSecret) {
      body.set('client_secret', config.oauth.clientSecret);
    }

    const { data } = await axios.post(config.oauth.tokenEndpoint!, body.toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: config.api.timeoutMs,
    });
    const tokens = normalizeOAuthTokenResponse(data);

    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.authMethod = 'oauth';
      req.session.tokens = tokens;
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        res.redirect(flow.redirectTo ?? config.oauth.postLoginRedirect);
      });
    });
  } catch (err) {
    next(err);
  }
});
