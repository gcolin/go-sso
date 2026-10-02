# Security policy

## Reporting

Please report security issues privately to the maintainers of your deployment
(or open a private advisory on GitHub if the repository enables that).

Do not file public issues that include exploit details for unpatched flaws.

## Scope

This project is an identity provider. Treat deployment misconfiguration
(open registration, weak admin password, `autoProvision` with untrusted IdPs,
HTTP cookies without Secure) as high severity in production.

See [docs/security.md](docs/security.md).
