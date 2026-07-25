FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates
ENV GOPROXY=direct
WORKDIR /src/orbit/orbit-api-gateway
COPY orbit/orbit-auth /src/orbit/orbit-auth
COPY orbit/orbit-observability /src/orbit/orbit-observability
COPY orbit/orbit-api-gateway/go.mod orbit/orbit-api-gateway/go.sum ./
RUN go mod download
COPY orbit/orbit-api-gateway/ .
RUN CGO_ENABLED=0 go build -o /gateway ./cmd/gateway

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /gateway /app/gateway
COPY orbit/orbit-api-gateway/openapi /app/openapi
EXPOSE 10120 10121
CMD ["/app/gateway"]
