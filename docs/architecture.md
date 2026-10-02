# Architecture

## Overview

`datanode-sso` is a single process that:

1. Loads `sso-server.json` (users, OAuth clients, IdPs, mail, RSA keys).
2. Serves HTTP under the context path derived from `server.publicBaseUrl`.
3. Persists admin/user changes back to the same JSON file (atomic save).

There is no external database. Authorization codes, pending OAuth states, and CSRF/session material live in memory (or JWT cookies) and are lost on restart — durable state is the config file.

```text
                    ┌─────────────────────────────────────┐
   Browser / RP ───►│  httpapi.Server  (routes + HTML)    │
                    └──────────────┬──────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
   security.*                 oauth.*                     mail.*
   (users, JWT,               (authorize,                 (SMTP,
    session, TOTP,             token, PKCE,                verify)
    CSRF)                      external IdP)
         │                         │
         └────────────┬────────────┘
                      ▼
                 config.AppConfig  ←→  sso-server.json
```

## Packages

| Package | Role |
|---------|------|
| `cmd/datanode-sso` | `main`: serve, `init-config`, `hash-password`, `ensure-signing-keys` |
| `internal/runtime` | Wires config → registries → HTTP server |
| `internal/httpapi` | Route table, HTML forms, JSON APIs, CSRF check |
| `internal/oauth` | OAuth service, client registry, external IdP, in-memory stores |
| `internal/security` | Password hashing, RSA JWT, sessions, user registry, TOTP |
| `internal/mail` | SMTP send + email verification tokens |
| `internal/config` | Schema, defaults, validate, load/save |
| `internal/model` | Shared structs (`User`, `OAuthClient`, `IdentityProvider`) |
| `internal/templates` + `mustache` + `i18n` | HTML rendering |
| `internal/themes` | Resolve theme id → disk overrides + static |
| `web/` | `embed.FS` for base Mustache/CSS/JS/i18n |

## Request lifecycle (HTML login)

1. Unauthenticated hit to a protected page or `/oauth/authorize` → redirect to `/login`.
2. Login form POST → CSRF validated → password check → optional 2FA cookie → session JWT cookie.
3. If an OAuth authorize was pending, resume consent / code issuance.
4. Access token is an RS256 JWT; resource servers validate via JWKS (`kid=sso-rsa-key`).

## Themes

- **Base** UI is embedded (`web/`).
- **Named themes** (`themes/{id}/`) override Mustache partials and serve `/themes/{id}/static/...`.
- Client `theme` field selects branding for login/consent/register for that RP.

## Testing

Fixtures in `internal/testsupport` build an in-memory runtime with temp config. HTTP tests use `httptest` against `httpapi.Server` without opening a port.
