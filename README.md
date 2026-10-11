# orbit-api-gateway

[![CI](https://github.com/manovaspace/orbit-api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/manovaspace/orbit-api-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Public REST edge for Orbit Tier 2 — auth proxy, JWT validation helpers, rate-limited public auth routes, and OpenAPI discovery.

Part of the [Manova / Orbit](https://github.com/manovaspace) open toolkit.

Product-specific API routes are not bundled here; register them in your deployment binary, gateway plugins, or edge reverse-proxy config.

## Quick start (dev)

Requires [orbit-auth](https://github.com/manovaspace/orbit-auth) on gRPC and Redis (or dev memory limiter).

```bash
export AUTH_GRPC_ADDR=localhost:10100
export JWT_PUBLIC_KEYS_DIR=./secrets/jwt-public-keys
export DEPLOYMENT_ENVIRONMENT=dev
go run ./cmd/gateway
```

The gateway verifies Orbit Auth RS256 access tokens using public PEM files in
`JWT_PUBLIC_KEYS_DIR` and publishes them at `/.well-known/jwks.json`. Name each
PEM `<kid>.pem`. It does not receive the signing private key.

For key rotation, add the new `<kid>.pem` while retaining the current key, then
restart the gateway before switching Orbit Auth to the new private key and
`JWT_ACTIVE_KEY_ID`. Keep the old public key until existing access tokens and
JWKS caches have expired; see the shared [token package guide](../orbit-auth/token/README.md).

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/auth/otp/request` | Proxies to `orbit-auth` `RequestOTP` |
| `POST` | `/api/v1/auth/otp/verify` | Proxies to `orbit-auth` `VerifyOTP` |
| `POST` | `/api/v1/auth/login` | Proxies to `orbit-auth` `LoginWithPassword` |
| `POST` | `/api/v1/auth/token/refresh` | Proxies to `orbit-auth` `RefreshToken` |
| `GET` | `/.well-known/jwks.json` | Publishes public RS256 verification keys for Orbit access tokens |
| `POST` | `/api/v1/system/ownership/challenge` | In-memory 6-digit OTP (10m TTL). **Does not send email.** Alias: `/api/v1/admin/challenge` |
| `POST` | `/api/v1/system/ownership/verify` | Verify in-memory code; fingerprint is not a signing secret. Alias: `/api/v1/admin/verify` |
| `POST` | `/api/v1/dev/onboard/claim` | Workstation onboarding claim (aliases: `/api/v1/onboard/claim`, `/v1/onboard/claim`; supports `Idempotency-Key` header) |
| `GET` | `/` | Serves raw canonical `install.sh` shell script (`text/x-shellscript`) |
| `GET` | `/api/v1/openapi/gateway.yaml` | OpenAPI 3.1 specification schema |
| `GET` | `/api/v1/openapi/manifest.json` | API gateway discovery manifest |
| `GET` | `/healthz`, `/readyz` | Liveness & readiness on dedicated health port `10121` (`HEALTH_PORT`) |

Default HTTP API: `localhost:10120` (`HTTP_PORT`) · Health: `localhost:10121` (`HEALTH_PORT`).

## Documentation

- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Security: [SECURITY.md](./SECURITY.md)
- Platform docs: https://manovaspace.github.io/docs/

## License

MIT — see [LICENSE](./LICENSE).
