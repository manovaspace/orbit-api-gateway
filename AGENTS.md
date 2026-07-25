# orbit-api-gateway — Agent Guide

REST edge for Orbit Tier 2 — auth proxy, rate limits, OpenAPI. Product backends mount outside this repo.

Status: `beta`.

## Commands

```bash
export AUTH_GRPC_ADDR=localhost:10100
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
go run ./cmd/gateway
go test ./...
```

See [README](./README.md) and [.env.example](./.env.example).
