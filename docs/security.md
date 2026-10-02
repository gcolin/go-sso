# Security model

## Passwords

- Stored as `pbkdf2-sha256$iterations$salt$hash` or `pbkdf2-sha512$…`.
- Compatible with hashes imported from Keycloak (including Java UTF-16BE salt quirks where supported).
- Generate with: `datanode-sso hash-password 'secret'`.

## Session JWT

- Cookie holds an RS256 JWT signed with `security.ssoPrivateKeyBase64`.
- Public key published at `/oauth/jwks`.
- TTL: `security.sessionTtlMinutes`. Use `sessionCookieSecure: true` on HTTPS.

## CSRF

State-changing HTML POSTs require a CSRF token:

- Cookie `sso_csrf` (signed JWT bound to the session user id).
- Matching form field / header checked in `httpapi`.

OAuth consent decisions are bound to the authenticated user and a `request_id` so a stolen consent form cannot approve another user’s authorize request.

## Rate limiting

Login attempts are limited by `loginRateLimitMaxAttempts` within `loginRateLimitWindowSeconds` (per identity / IP as implemented).

## TOTP 2FA

- Users enable TOTP from the profile UI (secret + QR).
- Login may issue a short-lived pending cookie until `/login/2fa` succeeds.
- Disabling 2FA requires a step-up (password and/or TOTP) so a stolen session alone cannot remove 2FA.

## Federation policy

`ResolveExternalLogin` (high level):

- Existing `(authProvider, externalSubject)` → login that user.
- Same email already bound to **another** IdP → refuse (`error.external.already_linked`, message includes the other provider name).
- Verified local password account → anonymous IdP login **cannot** silently link; user must be signed in (session-bound link).
- Unverified local account → IdP email proves ownership; password/2FA wiped then IdP linked (anti-squatting).
- Unknown email → create user only if `federation.autoProvision`.

External login always uses authorization code + **PKCE S256**.

## Email verification

When mail is enabled and verification is required, users with `emailVerified=false` cannot complete normal login until they follow the signed link (TTL: `emailVerificationTtlHours`).

## Operational checklist

- Unique RSA keys per environment; rotate by regenerating and updating JWKS consumers.
- Do not expose admin without TLS + strong admin password / IdP.
- Keep IdP `redirect_uri` exact-match with `{publicBaseUrl}/auth/callback/{id}`.
- Prefer `autoProvision=false` until you trust IdP email guarantees.
