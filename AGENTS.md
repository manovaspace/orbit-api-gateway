# orbit-api-gateway — Agent Guide

REST edge for Orbit Tier 2 — auth proxy, rate limits, OpenAPI discovery. **Product routes are not mounted in this binary** (Kaazhe and other backends serve their own HTTP until a future proxy lands).

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

## Commands

```bash
export AUTH_GRPC_ADDR=localhost:10100
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
go run ./cmd/gateway
go test ./...
```

See [README](./README.md) and [.env.example](./.env.example).
