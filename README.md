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
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
go run ./cmd/gateway
```

Default HTTP: `localhost:10120` · health: `localhost:10121`

## Documentation

- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Security: [SECURITY.md](./SECURITY.md)
- Platform docs: https://manovaspace.github.io/docs/

## License

MIT — see [LICENSE](./LICENSE).
