# orbit-api-gateway — Agent Guide

REST edge for Orbit Tier 2 — auth proxy, rate limits, OpenAPI discovery. **Product routes are not mounted in this binary** (product backends serve their own HTTP until a future proxy lands).

Status: `beta`.

## Contracts

Public HTTP is **OpenAPI-first**. Commit the OpenAPI artifact under `openapi/`; serve it at `/api/v1/openapi/gateway.yaml`. Scalar handbook/infra embedding is **planned** — do not hand-maintain endpoint tables.

The spec includes stable `operationId` values (`authLogin`, `authOtpRequest`, `authOtpVerify`, `authTokenRefresh`) and shared schemas (`TokenPair`, `OtpRequestResponse`, `ErrorEnvelope`). **Do not rename operationIds** without coordinating `@orbit/contracts` codegen in orbit-frontend (vendor + regenerate).

`internal/httpapi/openapi_test.go` parses the YAML and asserts path/method/`operationId` parity with `platformOpenAPIRoutes` (keep that table aligned with `NewServer` auth registrations).

| Topic | Path |
| --- | --- |
| OpenAPI-first | `handbook/docs/orbit/guides/openapi-first.md` |
| Scalar rendering | `handbook/docs/orbit/architecture/openapi-rendering.md` |
| ADR-015 | `handbook/docs/orbit/decisions/015-orbit-api-gateway.md` |

Agent routing: `openapi` / `orbit-api-gateway` in `handbook/cursor/agent-routing.yaml`.

## Endpoints

| Method | Path | Role |
| --- | --- | --- |
| `POST` | `/api/v1/auth/otp/request` | Upstream `orbit-auth` RequestOTP |
| `POST` | `/api/v1/auth/otp/verify` | Upstream `orbit-auth` VerifyOTP |
| `POST` | `/api/v1/auth/login` | Upstream `orbit-auth` LoginWithPassword |
| `POST` | `/api/v1/auth/token/refresh` | Upstream `orbit-auth` RefreshToken |
| `POST` | `/api/v1/system/ownership/challenge` | In-memory 6-digit OTP (10m TTL). **Does not send email.** Alias: `/api/v1/admin/challenge` |
| `POST` | `/api/v1/system/ownership/verify` | Verify in-memory code; fingerprint is not a signing secret. Alias: `/api/v1/admin/verify` |
| `POST` | `/api/v1/dev/onboard/claim` | Workstation onboarding claim (aliases: `/api/v1/onboard/claim`, `/v1/onboard/claim`; supports `Idempotency-Key` header) |
| `GET` | `/` | Canonical installer script (`text/x-shellscript`) |
| `GET` | `/api/v1/openapi/gateway.yaml` | OpenAPI 3.1 specification schema |
| `GET` | `/api/v1/openapi/manifest.json` | API gateway discovery manifest |
| `GET` | `/healthz`, `/readyz` | Liveness & readiness on dedicated health port `10121` (`HEALTH_PORT`) |

## Commands

```bash
export AUTH_GRPC_ADDR=localhost:10100
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
export HTTP_PORT=10120
export HEALTH_PORT=10121
go run ./cmd/gateway
go test ./...
```

See [README](./README.md) and [.env.example](./.env.example).
