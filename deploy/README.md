# Docker deploy

1. Build a static Linux binary into this directory (name must be `datanode-sso`):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o deploy/datanode-sso ./cmd/datanode-sso
```

For Raspberry Pi / arm64:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o deploy/datanode-sso ./cmd/datanode-sso
```

2. Place `sso-server.json` and `themes/` next to `docker-compose.yml` (or edit the volume paths).

3. Start:

```bash
cd deploy
docker compose up -d --build
curl -sS http://127.0.0.1:8080/api/health
```

The image is `FROM scratch` plus a CA bundle (needed for outbound HTTPS to Google, Microsoft, Yahoo, SMTP STARTTLS, etc.).
