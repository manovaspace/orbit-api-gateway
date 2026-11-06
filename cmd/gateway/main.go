package main

import (
	"context"
	"os"
	"strings"

	observability "github.com/manovaspace/orbit-observability"
	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
	"github.com/redis/go-redis/v9"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/clock"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/httpapi"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ids"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/jwks"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/memory"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

var version = "dev"

func main() {
	ctx := context.Background()
	if err := observability.Configure(observability.ConfigFromEnv("orbit-api-gateway", version)); err != nil {
		panic(err)
	}
	log := observability.Logger()

	if os.Getenv("JWT_SECRET") == "" && os.Getenv("DEPLOYMENT_ENVIRONMENT") != "dev" {
		log.Error("JWT_SECRET is required outside DEPLOYMENT_ENVIRONMENT=dev")
		os.Exit(1)
	}

	authAddr := envOr("AUTH_GRPC_ADDR", "localhost:10010")
	dialOpts := append(observability.GRPCDialOptions(), observability.InternalAuthDialOption())
	authClient, err := auth.NewClient(authAddr, dialOpts...)
	if err != nil {
		log.Error("auth client failed", "error", err)
		os.Exit(1)
	}
	authClient.AuthHTTPURL = envOr("AUTH_HTTP_URL", "http://localhost:10011")

	var limiter domain.Limiter
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: addr})
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Error("redis ping failed", "error", err)
			os.Exit(1)
		}
		limiter = ratelimit.New(ratelimiting.NewRedisLimiter(rdb))
		log.Info("rate limiting enabled", "redis", addr)
	} else if os.Getenv("DEPLOYMENT_ENVIRONMENT") == "dev" {
		limiter = ratelimit.New(ratelimiting.NewMemoryLimiter())
		log.Info("rate limiting using memory limiter (dev, no REDIS_ADDR)")
	} else {
		log.Error("REDIS_ADDR is required outside DEPLOYMENT_ENVIRONMENT=dev")
		os.Exit(1)
	}

	svc := application.NewService(application.Deps{
		Auth:       authClient,
		Orgs:       authClient,
		Signup:     authClient,
		Flags:      authClient,
		Limiter:    limiter,
		Clock:      clock.New(),
		Codes:      ids.New(),
		Challenges: memory.NewChallenges(),
		Claims:     memory.NewClaims(),
		Assets:     assets.New("openapi"),
		Audit:      memory.NewAuditStore(),
		Logger:     func(msg string, args ...any) { log.Info(msg, args...) },
	})

	dev := os.Getenv("DEPLOYMENT_ENVIRONMENT") == "dev"
	srv := httpapi.New(svc, httpapi.Options{
		TrustProxy:  strings.EqualFold(os.Getenv("RATE_LIMIT_TRUST_PROXY"), "true"),
		JWTSecret:   resolveJWTSecret(os.Getenv("JWT_SECRET"), dev),
		StaffSecret: os.Getenv("STAFF_SECRET"),
	})
	if dir := os.Getenv("JWT_PUBLIC_KEYS_DIR"); dir != "" {
		doc, err := jwks.Load(dir)
		if err != nil {
			log.Error("jwks keys failed", "error", err)
			os.Exit(1)
		}
		srv.ServeJWKS(doc.Body())
		log.Info("jwks published", "keys", doc.Keys())
	} else if !dev {
		log.Error("JWT_PUBLIC_KEYS_DIR is required outside DEPLOYMENT_ENVIRONMENT=dev")
		os.Exit(1)
	}

	httpPort := envOr("HTTP_PORT", "10001")
	healthPort := envOr("HEALTH_PORT", "10014")

	healthServer := httpapi.NewHealth()

	go func() {
		log.Info("http listening", "port", httpPort)
		if err := srv.Listen(":" + httpPort); err != nil {
			log.Error("http failed", "error", err)
		}
	}()
	go func() {
		if err := healthServer.Listen(":" + healthPort); err != nil {
			log.Error("health failed", "error", err)
		}
	}()

	observability.WaitForSignal(observability.ShutdownConfig{
		OnShutdown: []func(context.Context) error{
			srv.Shutdown,
			healthServer.Shutdown,
			func(context.Context) error { return authClient.Close() },
		},
	})
}

// devInsecureJWTSecret is the fallback the edge has always used in dev when
// JWT_SECRET is unset.
const devInsecureJWTSecret = "dev-insecure-change-me"

// resolveJWTSecret applies the dev fallback. Outside dev an empty secret is
// already a startup error, so the middleware never sees one.
func resolveJWTSecret(secret string, dev bool) string {
	if secret != "" {
		return secret
	}
	if dev {
		return devInsecureJWTSecret
	}
	return ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
