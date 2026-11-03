# Standalone image build (GitHub/GHCR). Local monorepo replace dirs are stripped;
# public manovaspace modules are resolved at the versions pinned in go.mod.
FROM golang:1.27.3-alpine AS builder
RUN apk add --no-cache git ca-certificates
ENV GOPROXY=https://proxy.golang.org,direct
ENV GONOSUMDB=github.com/manovaspace/*
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN set -euo pipefail \
	&& go mod edit -dropreplace=github.com/manovaspace/orbit-auth \
	&& go mod edit -dropreplace=github.com/manovaspace/orbit-observability \
	&& go mod edit -dropreplace=github.com/manovaspace/orbit-rate-limiting \
	&& go mod download all \
	&& CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /gateway ./cmd/gateway

FROM alpine:3.24
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /gateway /app/gateway
COPY --from=builder /src/openapi /app/openapi
EXPOSE 10120 10121
USER nobody
CMD ["/app/gateway"]
