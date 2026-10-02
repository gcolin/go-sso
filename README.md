# go-sso (Datanode SSO)

[![CI](https://github.com/gcolin/go-sso/actions/workflows/ci.yml/badge.svg)](https://github.com/gcolin/go-sso/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Self-hosted **OAuth 2.0 / OIDC-style identity provider** in Go: local accounts, TOTP 2FA, HTML login UI, admin console, SMTP verification, and external IdP federation (Google, Microsoft, Yahoo, …).

Configuration is a single JSON file (`sso-server.json`). No database required.

**Licence:** [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). See [NOTICE](NOTICE).

---

## Features

| Area | Capabilities |
|------|----------------|
| OAuth 2.0 | Authorization code + **PKCE S256**, client credentials, discovery, JWKS, userinfo, logout |
| Sessions | RS256 JWT cookie, configurable TTL, Secure cookie flag |
| Users | Local password (PBKDF2-SHA256/512), optional TOTP 2FA, admin CRUD |
| Registration | Optional public signup + email verification (JWT link) |
| Federation | Configurable OAuth/OIDC IdPs; link or auto-provision |
| UI | Embedded Mustache (FR/EN) + on-disk **themes** (Keycloak-style) |
| Admin | HTML settings (server, security, mail, federation) + clients/users |
| Security | Login rate limit, CSRF (JWT cookie bound to session), consent bound to user |

---

## Quick start

```bash
git clone https://github.com/gcolin/go-sso.git
cd go-sso
go build -o datanode-sso ./cmd/datanode-sso

./datanode-sso init-config sso-server.json   # generates RSA keys + admin@example.com
./datanode-sso                               # http://localhost:8080/sso (see publicBaseUrl)
```

Default admin (from `init-config`): check the CLI output / hashed password in the generated file.

Useful commands:

```bash
./datanode-sso hash-password 'my-secret'
./datanode-sso ensure-signing-keys sso-server.json
```

Environment: `DATANODE_SSO_CONFIG` — path to the JSON config (default `./sso-server.json`).

---

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/architecture.md](docs/architecture.md) | Packages, request flow, themes |
| [docs/configuration.md](docs/configuration.md) | Full `sso-server.json` reference |
| [docs/oauth.md](docs/oauth.md) | OAuth endpoints & client integration |
| [docs/security.md](docs/security.md) | Passwords, JWT, CSRF, federation policy |
| [docs/deployment.md](docs/deployment.md) | Binary, Docker, reverse proxy |
| [docs/login-callflows.md](docs/login-callflows.md) | Sequence diagrams (login, register, IdP) |
| [docs/federation-google-microsoft.md](docs/federation-google-microsoft.md) | IdP setup (Google, Microsoft, Facebook, Yahoo) |
| [deploy/README.md](deploy/README.md) | Container build notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev workflow & PR expectations |

Example config (no real keys): [`sso-server.example.json`](sso-server.example.json).

---

## Tests

```bash
go test ./... -count=1
go vet ./...
```

CI runs the same checks on every push/PR (`.github/workflows/ci.yml`).

---

## Module layout

```
cmd/datanode-sso/     CLI + HTTP server entrypoint
web/                  embedded Mustache, CSS/JS, i18n (base UI)
themes/               sample on-disk themes (not embedded in the binary)
deploy/               Dockerfile + compose example
docs/                 documentation
internal/config/      load / save / validate AppConfig
internal/model/       User, OAuthClient, IdentityProvider
internal/security/    passwords, JWT, session, users, TOTP, CSRF helpers
internal/oauth/       PKCE, stores, authorize/token, external IdP
internal/mail/        SMTP + verification tokens
internal/themes/      theme resolution
internal/mustache/    Mustache engine
internal/i18n/        .properties bundles
internal/templates/   page rendering
internal/httpapi/     HTTP routes & HTML handlers
internal/runtime/     composition root
internal/testsupport/ shared test fixtures
```

---

## Context path

Routes are served under the path of `server.publicBaseUrl`:

- `http://localhost:8080/sso` → `/sso/oauth/authorize`, `/sso/login`, …
- `https://oauth.example.com` (no path) → `/oauth/authorize`, `/login`, …

`/` redirects into that context path when a path prefix is configured.

---

## Themes

Public pages resolve a theme from:

1. `oauth.clients[].theme` when `client_id` is known  
2. else `server.defaultTheme`  
3. else `base` (embedded Pico CSS)

Named themes live **on disk** next to `sso-server.json` (see `server.themesDir`):

```text
sso-server.json
themes/
  tregor/
    theme.json
    mustache/…
    static/…
```

This repository ships sample themes under `themes/`. Copy them beside your production config.

---

## Reverse proxy

Terminate TLS at your proxy; set:

- `server.publicBaseUrl` to the public HTTPS origin (and path if any)
- `security.sessionCookieSecure: true` behind HTTPS

Health check: `GET {publicBaseUrl}/api/health` → `200`.

---

## Related

Originally a Go port of the Java Datanode SSO (`datanode-sso-*`). This repository is the standalone, AGPL-licensed distribution intended for GitHub.
