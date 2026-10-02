# Deployment

## Binary

```bash
go build -trimpath -ldflags='-s -w' -o datanode-sso ./cmd/datanode-sso
export DATANODE_SSO_CONFIG=/etc/sso/sso-server.json
./datanode-sso
```

Place themes next to the config (or set `server.themesDir`):

```text
/etc/sso/
  sso-server.json
  themes/
    tregor/…
```

## Docker

See [deploy/README.md](../deploy/README.md) and [deploy/docker-compose.yml](../deploy/docker-compose.yml).

Typical pattern:

- Build a static binary into `deploy/datanode-sso`.
- Image = scratch + CA certificates + binary.
- Bind-mount **config** and **themes** from the host (never bake secrets into the image).

## Reverse proxy (HTTPS)

Example nginx sketch:

```nginx
location / {
  proxy_pass http://127.0.0.1:8080;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Set in config:

- `server.publicBaseUrl`: `https://oauth.example.com` (or with `/sso` path if you terminate under a prefix)
- `security.sessionCookieSecure`: `true`

If the app is mounted under a path on the proxy, that path must match `publicBaseUrl`.

## Health

```bash
curl -fsS "$PUBLIC_BASE/api/health"
```

Expect HTTP 200.

## Upgrades

1. Backup `sso-server.json`.
2. Replace the binary / image.
3. Restart; JSON schema is additive — unknown fields may be dropped on save depending on loader behaviour, so keep backups.
4. Re-copy `themes/` if you rely on on-disk theme assets shipped in the repo.

## AGPL network use

If you run a modified version as a network service, AGPL-3.0 requires you to offer the Corresponding Source to users of that service. Keep this repository (or your fork) reachable and document how users obtain the source.
