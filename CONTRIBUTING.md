# Contributing

## Development

Requirements: Go 1.22+ (module declares `go 1.27`).

```bash
git clone https://github.com/gcolin/go-sso.git
cd go-sso
go test ./...
go build -o datanode-sso ./cmd/datanode-sso
./datanode-sso init-config sso-server.json
./datanode-sso
```

Do not commit `sso-server.json` (signing keys, passwords, IdP secrets). Use `sso-server.example.json` as the public template.

## Code style

- Keep changes focused; match existing package layout under `internal/`.
- Prefer table-driven tests next to the code they cover (`*_test.go`).
- HTTP handlers live in `internal/httpapi`; domain logic in `internal/security`, `internal/oauth`, `internal/mail`.
- User-facing strings go in `web/i18n/messages_*.properties` (FR + EN).

## Pull requests

1. Run `go test ./...` and fix failures.
2. Update docs under `docs/` when behaviour or config changes.
3. Note any migration impact on existing `sso-server.json` files.

## Licence

By contributing, you agree that your contributions are licensed under the
[GNU Affero General Public License v3](LICENSE) (AGPL-3.0).
