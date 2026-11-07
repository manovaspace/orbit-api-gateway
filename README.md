# orbit-api-gateway

[![CI](https://github.com/manovaspace/orbit-api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/manovaspace/orbit-api-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

Public REST edge for Orbit Tier 2 — auth proxy, JWT validation helpers, rate-limited public auth routes, and OpenAPI discovery.

Part of the [Manova / Orbit](https://github.com/manovaspace) open toolkit.

Product-specific API routes are not bundled here; register them in your deployment binary, gateway plugins, or edge reverse-proxy config. The gateway itself does not proxy or stream: it answers auth, ownership, onboarding and static assets.

## Quick start (dev)

Requires [orbit-auth](https://github.com/manovaspace/orbit-auth) on gRPC and Redis (or dev memory limiter).

```bash
export AUTH_GRPC_ADDR=localhost:10010
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
go run ./cmd/gateway
```

HTTP runs on **Fiber v3** fronting the same `net/http` handlers as before, so routes, status codes, headers and bodies are unchanged. `internal/infrastructure/httpapi/contract_test.go` holds the contract captured from the previous server.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/v1/auth/otp/request` | Proxies to `orbit-auth` `RequestOTP` |
| `POST` | `/api/v1/auth/otp/verify` | Proxies to `orbit-auth` `VerifyOTP` |
| `GET` | `/.well-known/jwks.json` | Public access-token keys from `JWT_PUBLIC_KEYS_DIR` |
| `POST` | `/api/v1/auth/login` | Proxies to `orbit-auth` `LoginWithPassword` (`identifier`: email or E.164 mobile; `email` deprecated) |
| `POST` | `/api/v1/auth/token/refresh` | Proxies to `orbit-auth` `RefreshToken` |
| `POST` | `/api/v1/auth/signup` | Proxies to `orbit-auth` `SignupService.RegisterWithEmail`. Unauthenticated; same 202 for new and existing addresses; disabled sign-up answers 404 |
| `POST` | `/api/v1/auth/signup/verify` | Proxies to `orbit-auth` `SignupService.VerifySignup`; returns a token pair |
| `GET` | `/api/v1/orgs` | Proxies to `orbit-auth` `OrgService.ListMyOrgs` (bearer access token) |
| `POST` | `/api/v1/orgs` | Proxies to `orbit-auth` `OrgService.CreateOrg` (`name`) |
| `GET` | `/api/v1/orgs/{org_id}/members` | Proxies to `orbit-auth` `OrgService.ListMembers` (non-member is 404) |
| `POST` | `/api/v1/orgs/{org_id}/members` | Proxies to `orbit-auth` `OrgService.AddMember` (`user_id`); owner or admin only, else 403 |
| `DELETE` | `/api/v1/orgs/{org_id}/members/{user_id}` | Proxies to `orbit-auth` `OrgService.RemoveMember`; owner, an admin removing a plain member, or the member themselves; last active owner is 409 |
| `POST` | `/api/v1/orgs/{org_id}/members/{user_id}/suspend` | Proxies to `orbit-auth` `OrgService.SuspendMember`; owner or an admin suspending a plain member |
| `PUT` | `/api/v1/orgs/{org_id}/members/{user_id}/role` | Proxies to `orbit-auth` `OrgService.SetMemberRole` (`role`: `owner`, `admin`, `member`); only an owner grants `owner` or `admin` |
| `POST` | `/api/v1/orgs/{org_id}/invites` | Proxies to `orbit-auth` `OrgService.InviteMember` (`email`); owner or admin only, else 403 |
| `GET` | `/api/v1/orgs/{org_id}/invites` | Proxies to `orbit-auth` `OrgService.ListInvites` |
| `DELETE` | `/api/v1/orgs/{org_id}/invites/{invite_id}` | Proxies to `orbit-auth` `OrgService.RevokeInvite` |
| `POST` | `/api/v1/invites/accept` | Proxies to `orbit-auth` `OrgService.AcceptInvite` (`token`) |
| `POST` | `/api/v1/session/org` | Proxies to `orbit-auth` `OrgService.SelectOrg` (`org_id`, `refresh_token`); returns a token pair |
| `POST` | `/api/v1/system/ownership/challenge` | In-memory 6-digit OTP (10m TTL). **Does not send email.** Alias: `/api/v1/admin/challenge` |
| `POST` | `/api/v1/system/ownership/verify` | Verify in-memory code; fingerprint is not a signing secret. Alias: `/api/v1/admin/verify` |
| `POST` | `/api/v1/dev/onboard/claim` | Workstation onboarding claim (aliases: `/api/v1/onboard/claim`, `/v1/onboard/claim`; supports `Idempotency-Key` header) |
| `GET` | `/` | Serves raw canonical `install.sh` shell script (`text/x-shellscript`) |
| `GET` | `/api/v1/openapi/gateway.yaml` | OpenAPI 3.1 specification schema |
| `GET` | `/api/v1/openapi/manifest.json` | API gateway discovery manifest |
| `GET` | `/healthz`, `/readyz` | Liveness & readiness on dedicated health port `10014` (`HEALTH_PORT`) |

Default HTTP API: `localhost:10001` (`HTTP_PORT`) · Health: `localhost:10014` (`HEALTH_PORT`).

## Layout

```
cmd/gateway/                        wiring only: env, adapters, servers
internal/domain/                    edge types and ports (AuthService, OrgService,
                                    SignupService, Limiter, Clock, CodeGenerator,
                                    ChallengeStore, ClaimCache, Assets)
internal/application/               auth, signup, organization, ownership, onboarding,
                                    asset and rate-limit use cases
internal/infrastructure/
  assets/                           embedded installer, OpenAPI artifacts
  auth/                             orbit-auth gRPC adapter and status mapping
  clock/                            system clock adapter
  httpapi/                          Fiber v3 edge and health server (net/http handlers)
  ids/                              six-digit challenge codes
  jwks/                             public verification key document
  memory/                           in-process challenge and claim stores
  ratelimit/                        orbit-rate-limiting adapter
```

The domain imports no infrastructure package. The application layer receives
every dependency through `application.Deps`, and `cmd/` only wires adapters.
`.golangci.yml` `depguard` rules enforce both boundaries.

## Development

```bash
go test ./... -race -count=1
```

Tests use fakes and an in-process gRPC stand-in, so they need no service. The
service stores nothing outside the process: there is no Postgres, no
migrations, no sqlc and no event bus. See [AGENTS.md](./AGENTS.md) for the full
configuration list.

## Documentation

- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)
- Security: [SECURITY.md](./SECURITY.md)
- Platform docs: https://manovaspace.github.io/docs/

## License

MIT — see [LICENSE](./LICENSE).
