# Configuration reference

File: `sso-server.json` (or path in `DATANODE_SSO_CONFIG`).

Generate a valid starter with:

```bash
./datanode-sso init-config sso-server.json
```

Never commit real keys or IdP secrets. Public template: [`sso-server.example.json`](../sso-server.example.json).

## `server`

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | Bind address (default `0.0.0.0`) |
| `port` | int | Listen port (default `8080`) |
| `publicBaseUrl` | string | Public origin **including** optional path prefix (e.g. `https://idp.example.com` or `http://localhost:8080/sso`) |
| `title` | string | Product title in UI |
| `defaultLocale` | string | `fr` / `en` |
| `defaultTheme` | string | Theme id when client has none (`base`, `tregor`, …) |
| `themesDir` | string | Themes directory (absolute or relative to the config file) |
| `realm` | string | Optional legacy Keycloak-style callback path segment |

Context path = URL path of `publicBaseUrl`. Empty path → routes at `/`.

## `security`

| Field | Description |
|-------|-------------|
| `sessionCookieName` | Cookie name for the SSO session JWT |
| `sessionCookieSecure` | Set `true` behind HTTPS |
| `sessionTtlMinutes` | Session lifetime |
| `ssoPrivateKeyBase64` / `ssoPublicKeyBase64` | PKCS#1/SPKI RSA pair (Base64 DER) for JWT/JWKS |
| `loginRateLimitMaxAttempts` / `loginRateLimitWindowSeconds` | Brute-force window |
| `emailVerificationTtlHours` | Validity of verify-email links |
| `publicRegistrationEnabled` | Allow `/register` when mail is usable |
| `defaultUserMaxStorageBytes` | Optional quota hint for apps |

## `oauth`

| Field | Description |
|-------|-------------|
| `authorizationCodeTtlSeconds` | Auth code lifetime |
| `accessTokenTtlSeconds` | Access token JWT lifetime |
| `clients[]` | Registered RPs |

### Client object

| Field | Description |
|-------|-------------|
| `clientId` | Public client id |
| `displayName` | Shown on consent |
| `redirectUri` | Single exact redirect URI |
| `clientSecret` | If set → confidential client |
| `theme` | Optional theme id for login/consent |

## `federation`

| Field | Description |
|-------|-------------|
| `autoProvision` | Create user on first IdP login when email unknown |
| `defaultUserType` | `user` or `admin` for auto-provisioned accounts |
| `identityProviders[]` | External OAuth/OIDC providers |

### Identity provider object

| Field | Description |
|-------|-------------|
| `id` | Stable id (`google`, `microsoft`, …) — used in `/auth/callback/{id}` |
| `enabled` | Shown on login when true |
| `displayName` / `logo` | UI (`logo`: Bootstrap Icons class, e.g. `bi-google`) |
| `clientId` / `clientSecret` | IdP app credentials |
| `authorizationUrl` / `tokenUrl` / `userInfoUrl` | Endpoints |
| `scopes` | Space-separated; default OIDC-ish if empty |
| `emailClaim` / `nameClaim` / `subjectClaim` | Defaults `email` / `name` / `sub` |
| `redirectUri` | Optional override of `{publicBaseUrl}/auth/callback/{id}` |

See [federation-google-microsoft.md](federation-google-microsoft.md) for vendor tables.

## `mail`

| Field | Description |
|-------|-------------|
| `enabled` | Turn on SMTP |
| `smtpHost` / `smtpPort` | Server |
| `smtpUser` / `smtpPassword` | Auth (optional) |
| `fromName` / `fromAddress` | From header |
| `startTls` | Prefer STARTTLS |

Public registration requires mail (verification) when enabled in security settings.

## `users[]`

| Field | Description |
|-------|-------------|
| `id` | Stable user id (JWT `sub`) |
| `email` | Login identifier |
| `passwordHash` | `pbkdf2-sha256$…` or `pbkdf2-sha512$…` (optional if IdP-only) |
| `name` | Display name |
| `type` | `user` or `admin` |
| `totpSecret` | Base32 TOTP secret when 2FA enabled |
| `authProvider` / `externalSubject` | Federation binding |
| `emailVerified` | `false` blocks login until verified (when mail policy applies) |
| `maxStorageBytes` | Optional per-user override |

Admin HTML under `/admin/…` can edit most of these without hand-editing JSON.
