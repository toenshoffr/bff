# Angular ↔ Spring Boot BFF

A minimal Backend-for-Frontend (Node.js/Express/TypeScript) that sits between an
Angular SPA and a Spring Boot REST API, implementing the "token handler" pattern:

- **Browser ↔ BFF**: an opaque, `httpOnly`, `Secure`, `SameSite` session cookie.
  The browser (and any JS running in it) never sees an access or refresh token.
- **BFF ↔ Spring Boot API**: JWT access tokens, sent as `Authorization: Bearer <jwt>`.
  Tokens live only in server-side session storage and are refreshed transparently.

Two interchangeable, independently-configurable auth methods are included:

- **Username/password** — the BFF forwards credentials to a Spring Boot login
  endpoint and stores the JWTs it returns.
- **OAuth client (Authorization Code + PKCE)** — the BFF acts as a confidential
  OAuth client against your identity provider (Keycloak, Auth0, Okta, Spring
  Authorization Server, etc.) and stores the resulting JWTs.

Both can be enabled at once (`AUTH_METHODS=password,oauth`); the Angular app
chooses which login flow to present.

## Request flow

```
Angular SPA                    BFF (this app)                 Spring Boot API
     |  httpOnly session cookie      |        Bearer JWT              |
     |------------------------------>|------------------------------->|
     |         GET /api/orders       |         GET /orders            |
     |<------------------------------|<--------------------------------|
```

1. Angular calls the BFF's `/auth/login` (password) or redirects the browser to
   `/auth/oauth/login` (OAuth).
2. The BFF exchanges credentials/authorization code for a JWT access token (+
   refresh token) with the Spring Boot API / IdP, stores them server-side keyed
   by session, and sets an `httpOnly` cookie on the browser.
3. Angular calls `/api/**` on the BFF (same-origin from the browser's point of
   view) using the session cookie. The BFF resolves the session, refreshes the
   JWT if it's near expiry, and proxies the request to the Spring Boot API with
   `Authorization: Bearer <jwt>` attached.
4. The Spring Boot API never sees the session cookie, and the browser never
   sees the JWT.

## Setup

```bash
npm install
cp .env.example .env   # then edit values for your environment
npm run dev             # tsx watch, for local development
```

```bash
npm run build            # compiles to dist/
npm start                 # runs the compiled server
```

## Configuration

All configuration is via environment variables (see `.env.example` for the
full list with defaults). Key ones:

| Variable | Purpose |
|---|---|
| `FRONTEND_ORIGIN` | Exact origin of the Angular app (for CORS) |
| `API_BASE_URL` | Base URL of the Spring Boot REST API |
| `API_PROXY_PATH` | BFF path prefix proxied to the API (default `/api`) |
| `AUTH_METHODS` | `password`, `oauth`, or `password,oauth` |
| `SESSION_SECRET` | Secret used to sign the session cookie |
| `PASSWORD_LOGIN_PATH` / `PASSWORD_REFRESH_PATH` | Spring Boot endpoints the BFF calls for username/password login/refresh |
| `OAUTH_*` | Authorization/token endpoints, client id/secret, redirect URI, scopes |

Config is validated at startup with `zod`; missing/invalid values fail fast
with a readable error instead of a runtime crash later.

### Expected Spring Boot contract

- **Password login** (`POST {API_BASE_URL}{PASSWORD_LOGIN_PATH}`): accepts
  `{ "username": string, "password": string }`, returns
  `{ "accessToken": string, "refreshToken": string, "expiresIn": number, "user"?: object }`
  (snake_case `access_token`/`refresh_token`/`expires_in` is also accepted).
- **Password refresh** (`POST {API_BASE_URL}{PASSWORD_REFRESH_PATH}`): accepts
  `{ "refreshToken": string }`, returns the same shape as login.
- **OAuth**: standard OAuth2/OIDC Authorization Code + `refresh_token` grants
  against your IdP's token endpoint.
- **Proxied API calls**: any JWT-secured endpoint under `API_BASE_URL`, reached
  via the BFF at `{API_PROXY_PATH}/<path>` (e.g. BFF `/api/orders` → API
  `/orders`).

## Endpoints exposed by the BFF

| Method & path | Description |
|---|---|
| `GET /healthz` | Liveness check |
| `GET /auth/csrf` | Issues a CSRF token (cookie + JSON body) |
| `GET /auth/status` | `{ authenticated, authMethod, user }` for the current session |
| `POST /auth/login` | Username/password login (if `password` enabled) |
| `GET /auth/oauth/login` | Starts the OAuth Authorization Code + PKCE flow (if `oauth` enabled) |
| `GET /auth/oauth/callback` | OAuth redirect URI — exchanges the code for tokens |
| `POST /auth/logout` | Destroys the session |
| `ALL /api/**` | Authenticated reverse proxy to the Spring Boot API |

## CSRF

Cookies are the auth mechanism, so state-changing requests are protected with
a stateless double-submit cookie: call `GET /auth/csrf` once, then send the
returned token back as an `X-CSRF-Token` header on every `POST`/`PUT`/
`PATCH`/`DELETE` (including `/auth/login` and calls proxied through `/api`).

For quick local testing with tools like curl/Postman where fetching the CSRF
token first is inconvenient, set `CSRF_PROTECTION_ENABLED=false` in `.env`.
This disables the check entirely — it logs a warning on startup as a
reminder, and must never be set in a deployed environment.

## Angular integration notes

- Configure `HttpClient` to send cookies: `withCredentials: true` on requests
  (or globally via `withInterceptorsUsingFetch`/`HTTP_INTERCEPTORS`), and set
  the SPA's API base URL to the BFF's origin, not the Spring Boot API directly.
- Fetch `/auth/csrf` on app bootstrap and attach `X-CSRF-Token` via an
  `HttpInterceptor` for mutating requests.
- Password login: `POST /auth/login` with the credentials; on success, call
  `/auth/status` (or read the response body) to get the current user.
- OAuth login: navigate the browser to `/auth/oauth/login` (a full redirect,
  not an XHR) — the BFF handles the IdP round trip and redirects back to
  `OAUTH_POST_LOGIN_REDIRECT`.
- On a `401` from any `/api/**` call, treat the session as expired and route
  the user back to the login screen.

## Production notes

- The default session store is in-memory and single-instance only. For
  production, swap in a shared store (e.g. `connect-redis`) so sessions
  survive restarts and work across multiple BFF instances behind a load
  balancer.
- Run behind TLS and keep `COOKIE_SECURE=true` (the default) so the session
  cookie is only ever sent over HTTPS.
- `COOKIE_SAME_SITE=none` is only needed if the Angular app and BFF are on
  different sites; prefer serving them from the same site (even if different
  subdomains/ports) and `lax`/`strict` where possible.
