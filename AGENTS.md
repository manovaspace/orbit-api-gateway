---
read_with:
  - handbook/docs/orbit/architecture/contracts.md
  - handbook/docs/orbit/architecture/openapi-rendering.md
  - handbook/docs/orbit/decisions/015-orbit-api-gateway.md
  - handbook/docs/orbit/guides/openapi-first.md
---

# orbit-api-gateway — Agent Guide

REST edge for Orbit Tier 2 — auth proxy, rate limits, OpenAPI discovery. **Product routes are not mounted in this binary** (product backends serve their own HTTP until a future proxy lands).

Status: `beta`.

## Architecture

- `internal/domain` — the edge's types and ports: `AuthService`, `OrgService`, `SignupService` (upstream orbit-auth), `Limiter`, `Clock`, `CodeGenerator`, `ChallengeStore`, `ClaimCache`, `Assets`. It imports no infrastructure package, HTTP framework, environment or proto.
- `internal/application` — the auth, signup, organization, ownership, onboarding, static-asset and rate-limit use cases. It receives `application.Deps` and reads no environment variable.
- `internal/infrastructure` — adapters: `httpapi` (Fiber v3 edge and health server), `auth` (orbit-auth gRPC), `ratelimit` (orbit-rate-limiting memory/Redis), `memory` (challenge and claim stores), `assets` (embedded installer, OpenAPI artifacts), `jwks`, `clock`, `ids`.
- `cmd/gateway` — wiring only.
- `.golangci.yml` `depguard` rules enforce both boundaries. Do not weaken them to land a change.

Three paths are deliberately absent: no Postgres (so no migrations, no sqlc and no database integration tier), no event transport (Redis is used only for rate limiting, never for events), and no proxy or streaming route — the edge answers auth, ownership, onboarding and static assets only.

## HTTP

- Fiber v3 fronts the same `net/http` handlers this service ran before. Routing, status codes, headers and bodies are unchanged; `internal/infrastructure/httpapi/contract_test.go` holds the HTTP contract captured from the old `net/http` server, and its assertions were not edited for the migration.
- `adaptor.HTTPHandler` keeps `http.ServeMux` semantics (405 `Allow`, 404 bodies, the `GET /` installer catch-all) instead of Fiber's router.
- Timeouts: read 30s, write 30s, idle 60s. JSON bodies are capped at 64 KiB in the handlers; the Fiber `BodyLimit` (4 MiB) only bounds what the HTTP front buffers first, so keep it well above the handler cap.
- Response framing (chunked vs `Content-Length`, `Date`) comes from the server, not the handlers, and is not part of the contract.

## Contracts

Public HTTP is **OpenAPI-first**. Commit the OpenAPI artifact under `openapi/`; serve it at `/api/v1/openapi/gateway.yaml`. Scalar handbook/infra embedding is **planned** — do not hand-maintain endpoint tables.

The spec includes stable `operationId` values for every operation (`authLogin`, `authOtpRequest`, `authOtpVerify`, `authTokenRefresh`, `authSignup`, `authSignupVerify`, `orgList`, `orgCreate`, `orgMembersList`, `orgMemberAdd`, `orgMemberRemove`, `orgMemberSuspend`, `orgMemberRoleSet`, `orgSlugSet`, `tenantResolve`, `orgInviteCreate`, `orgInviteList`, `orgInviteRevoke`, `inviteAccept`, `sessionSelectOrg`) and shared schemas (`TokenPair`, `OtpRequestResponse`, `ErrorEnvelope`). **Do not rename operationIds** without coordinating `@orbit/contracts` codegen in orbit-frontend (vendor + regenerate).

`internal/infrastructure/httpapi/openapi_test.go` parses the YAML and asserts path/method/`operationId` parity with `platformOpenAPIRoutes` (keep that table aligned with `New` auth registrations).

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
| `POST` | `/api/v1/auth/login` | Upstream `orbit-auth` LoginWithPassword (`identifier`: email or E.164 mobile) |
| `POST` | `/api/v1/auth/token/refresh` | Upstream `orbit-auth` RefreshToken |
| `POST` | `/api/v1/auth/signup` | Upstream `orbit-auth` SignupService RegisterWithEmail. Unauthenticated; same 202 for new and existing addresses; disabled sign-up answers 404 |
| `POST` | `/api/v1/auth/signup/verify` | Upstream `orbit-auth` SignupService VerifySignup; returns `TokenPair` |
| `GET` | `/api/v1/orgs` | Upstream `orbit-auth` OrgService ListMyOrgs (bearer access token) |
| `POST` | `/api/v1/orgs` | Upstream `orbit-auth` OrgService CreateOrg (`name`, optional `slug`; bearer access token) |
| `GET` | `/api/v1/orgs/{org_id}/members` | Upstream `orbit-auth` OrgService ListMembers (bearer; non-member is 404) |
| `POST` | `/api/v1/orgs/{org_id}/members` | Upstream `orbit-auth` `OrgService.AddMember` (`user_id`); owner or admin only, else 403 |
| `DELETE` | `/api/v1/orgs/{org_id}/members/{user_id}` | Upstream `orbit-auth` `OrgService.RemoveMember`; owner, an admin removing a plain member, or the member themselves; last active owner is 409 |
| `POST` | `/api/v1/orgs/{org_id}/members/{user_id}/suspend` | Upstream `orbit-auth` `OrgService.SuspendMember`; owner or an admin suspending a plain member |
| `PUT` | `/api/v1/orgs/{org_id}/members/{user_id}/role` | Upstream `orbit-auth` `OrgService.SetMemberRole` (`role`: `owner`, `admin`, `member`); only an owner grants `owner` or `admin` |
| `PUT` | `/api/v1/orgs/{org_id}/slug` | Upstream `orbit-auth` `OrgService.SetOrgSlug` (`slug`); owner only. The old slug stays reserved and resolves |
| `GET` | `/api/v1/public/tenants/{slug}` | **Public.** Upstream `orbit-auth` `TenantService.ResolveTenant`; returns `org_id`, `slug`, `name`, `retired` only; cacheable 30 s; 404 for an unknown slug |
| `POST` | `/api/v1/orgs/{org_id}/invites` | Upstream `orbit-auth` OrgService InviteMember (`email`); owner or admin only, else 403 |
| `GET` | `/api/v1/orgs/{org_id}/invites` | Upstream `orbit-auth` OrgService ListInvites |
| `DELETE` | `/api/v1/orgs/{org_id}/invites/{invite_id}` | Upstream `orbit-auth` OrgService RevokeInvite |
| `POST` | `/api/v1/invites/accept` | Upstream `orbit-auth` OrgService AcceptInvite (`token`) |
| `POST` | `/api/v1/session/org` | Upstream `orbit-auth` OrgService SelectOrg (`org_id`, `refresh_token`); returns `TokenPair` |
| `POST` | `/api/v1/system/ownership/challenge` | In-memory 6-digit OTP (10m TTL). **Does not send email.** Alias: `/api/v1/admin/challenge` |
| `POST` | `/api/v1/system/ownership/verify` | Verify in-memory code; fingerprint is not a signing secret. Alias: `/api/v1/admin/verify` |
| `POST` | `/api/v1/dev/onboard/claim` | Workstation onboarding claim (aliases: `/api/v1/onboard/claim`, `/v1/onboard/claim`; supports `Idempotency-Key` header) |
| `GET` | `/` | Canonical installer script (`text/x-shellscript`) |
| `GET` | `/api/v1/openapi/gateway.yaml` | OpenAPI 3.1 specification schema |
| `GET` | `/api/v1/openapi/manifest.json` | API gateway discovery manifest |
| `GET` | `/healthz`, `/readyz` | Liveness & readiness on dedicated health port `10014` (`HEALTH_PORT`) |

## Configuration

- **Auth upstream:** `AUTH_GRPC_ADDR` (default `localhost:10010`).
- **Rate limiting:** `REDIS_ADDR` selects the Redis limiter; without it `DEPLOYMENT_ENVIRONMENT=dev` uses the memory limiter and anything else refuses to start. `RATE_LIMIT_TRUSTED_PROXIES` (comma-separated CIDRs or IPs) names the peers whose `X-Forwarded-For` is believed: from a trusted peer the client is the rightmost untrusted hop, otherwise the socket address is used and the header is ignored. `RATE_LIMIT_TRUST_PROXY=true` is deprecated: it trusts every peer and reads the first `X-Forwarded-For` entry.
- **Tokens:** `JWT_SECRET` is required outside dev (`dev-insecure-change-me` in dev). `JWT_PUBLIC_KEYS_DIR` publishes `/.well-known/jwks.json`; it is required outside dev.
- **Ports:** `HTTP_PORT` (default `10001`), `HEALTH_PORT` (default `10014`).

## Commands

```bash
export AUTH_GRPC_ADDR=localhost:10010
export JWT_SECRET=dev-insecure-change-me
export DEPLOYMENT_ENVIRONMENT=dev
export HTTP_PORT=10001
export HEALTH_PORT=10014
go run ./cmd/gateway
go test ./... -race -count=1
```

Tests use fakes and an in-process gRPC stand-in; none needs a service. There are no
database integration tests, so there is no release-check tier and no
`.github/allowed-skips.txt`. See [README](./README.md) and [.env.example](./.env.example).

## Storage and events

- No Postgres, no migrations, no SQL and no `docs/migrations.md`: nothing in this service persists beyond the process.
- Ownership challenges and onboarding claims live in `internal/infrastructure/memory` behind `domain.ChallengeStore` and `domain.ClaimCache`; both are lost on restart, exactly as before.
- No events. The service publishes and consumes nothing; do not wire `messagebus.Bus` without an ADR change.
