# OAuth 2.0 integration

## Discovery

```http
GET {publicBaseUrl}/.well-known/openid-configuration
GET {publicBaseUrl}/oauth/jwks
```

Issuer and endpoints are derived from `server.publicBaseUrl`.

## Authorization code + PKCE

1. Redirect the user to:

```text
{publicBaseUrl}/oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT
  &redirect_uri=https://app.example/callback
  &scope=openid
  &state=…
  &code_challenge=…
  &code_challenge_method=S256
```

2. User authenticates (and consents if required).
3. Browser returns to `redirect_uri?code=…&state=…`.
4. Exchange the code:

```http
POST {publicBaseUrl}/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=…
&redirect_uri=…
&client_id=…
&code_verifier=…
```

Confidential clients also send `client_secret` (or HTTP Basic).

## Client credentials

```http
POST {publicBaseUrl}/oauth/token
grant_type=client_credentials&client_id=…&client_secret=…
```

When the authorization request included scope `openid`, the token response also includes an OIDC `id_token` (JWT, RS256) with `aud` = `client_id`.

## Userinfo

```http
GET {publicBaseUrl}/oauth/userinfo
Authorization: Bearer <access_token>
```

## Logout

- HTML: `POST {publicBaseUrl}/logout` (CSRF)
- OAuth-style: `GET {publicBaseUrl}/oauth/logout?post_logout_redirect_uri=…` (URI must match a registered client redirect when restricted)

## Registering a client

Admin UI: **Clients** → create (`clientId`, `redirectUri`, optional secret & theme),  
or edit `oauth.clients` in JSON and restart / save via admin.

Only **one** `redirectUri` per client entry. For multiple environments, register multiple clients (`app-prod`, `app-dev`).

## Scopes & roles

Access tokens carry platform roles such as `platform:user` / `platform:admin` derived from the user `type`. Resource servers should validate JWT signature via JWKS (`kid=sso-rsa-key`).
