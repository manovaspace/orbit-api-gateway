package main

import (
	"context"
	"net/http"
	"os"

	observability "github.com/manovaspace/orbit-observability"
	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
	"github.com/manovaspace/orbit-api-gateway/internal/httpapi"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/redis/go-redis/v9"
)

func main() {
	ctx := context.Background()
	if err := observability.Configure(observability.ConfigFromEnv("orbit-api-gateway", "0.1.0")); err != nil {
		panic(err)
	}
	log := observability.Logger()

	if os.Getenv("JWT_SECRET") == "" && os.Getenv("DEPLOYMENT_ENVIRONMENT") != "dev" {
		log.Error("JWT_SECRET is required outside DEPLOYMENT_ENVIRONMENT=dev")
		os.Exit(1)
	}

	authAddr := envOr("AUTH_GRPC_ADDR", "localhost:10100")
	dialOpts := append(observability.GRPCDialOptions(), observability.InternalAuthDialOption())
	auth, err := authclient.NewClient(authAddr, dialOpts...)
	if err != nil {
		log.Error("auth client failed", "error", err)
		os.Exit(1)
	}

	var lim ratelimiting.Limiter
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb := redis.NewClient(&redis.Options{Addr: addr})
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Error("redis ping failed", "error", err)
			os.Exit(1)
		}
		lim = ratelimiting.NewRedisLimiter(rdb)
		log.Info("rate limiting enabled", "redis", addr)
	} else if os.Getenv("DEPLOYMENT_ENVIRONMENT") == "dev" {
		lim = ratelimiting.NewMemoryLimiter()
		log.Info("rate limiting using memory limiter (dev, no REDIS_ADDR)")
	} else {
		log.Error("REDIS_ADDR is required outside DEPLOYMENT_ENVIRONMENT=dev")
		os.Exit(1)
	}
	rl := httpapi.NewRateLimitConfig(lim)
	srv := httpapi.NewServer(httpapi.NewAuthHandlers(auth.API(), rl), rl)

	httpPort := envOr("HTTP_PORT", "10120")
	healthPort := envOr("HEALTH_PORT", "10121")

	mainServer := httpapi.NewHTTPServer(":"+httpPort, srv.Handler())
	healthMux := http.NewServeMux()
	healthMux.Handle("/healthz", observability.HealthHandler())
	healthMux.Handle("/readyz", observability.ReadinessHandler())
	healthServer := httpapi.NewHTTPServer(":"+healthPort, observability.HTTPMiddleware(healthMux))

	go func() {
		log.Info("http listening", "port", httpPort)
		if err := mainServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http failed", "error", err)
		}
	}()
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("health failed", "error", err)
		}
	}()

	observability.WaitForSignal(observability.ShutdownConfig{
		HTTPServer: mainServer,
		OnShutdown: []func(context.Context) error{
			func(context.Context) error {
				return healthServer.Shutdown(ctx)
			},
			func(context.Context) error {
				return auth.Close()
			},
		},
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
