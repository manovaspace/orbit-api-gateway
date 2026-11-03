package httpapi

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

type fakeFlagSource struct {
	set   domain.FlagSet
	err   error
	calls int
}

func (f *fakeFlagSource) ListFlags(context.Context) (domain.FlagSet, error) {
	f.calls++
	return f.set, f.err
}

func newFlagsEnv(t *testing.T, source domain.FlagSource, limiter domain.Limiter) string {
	t.Helper()
	svc := application.NewService(application.Deps{
		Flags:   source,
		Limiter: limiter,
		Assets:  assets.New("openapi"),
	})
	return serveOnLoopback(t, New(svc, Options{JWTSecret: "test-secret"}))
}

func TestFlagsReturnsTheUpstreamDocumentWithoutABearerToken(t *testing.T) {
	source := &fakeFlagSource{set: domain.FlagSet{
		Version: "2026-11-03T10:00:00Z",
		Flags: []domain.FeatureFlag{{
			Name:        "beta",
			Enabled:     true,
			Description: "Beta access",
		}},
	}}
	base := newFlagsEnv(t, source, nil)

	got := send(t, base, http.MethodGet, routeFlags, "", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", got.Status, got.Body)
	}
	want := `{"version":"2026-11-03T10:00:00Z","flags":[{"name":"beta","enabled":true,"description":"Beta access"}]}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("content-type = %q", got.ContentType)
	}
	if got.CacheControl != "no-cache" {
		t.Fatalf("cache-control = %q, want no-cache", got.CacheControl)
	}
	if source.calls != 1 {
		t.Fatalf("source calls = %d, want 1", source.calls)
	}
}

func TestFlagsReturns502WhenTheSourceFails(t *testing.T) {
	source := &fakeFlagSource{err: errors.New("orbit-auth down")}
	base := newFlagsEnv(t, source, nil)

	got := send(t, base, http.MethodGet, routeFlags, "", nil)
	if got.Status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %q)", got.Status, got.Body)
	}
	if got.Body != `{"error":"flags unavailable"}`+"\n" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.CacheControl != "no-cache" {
		t.Fatalf("cache-control = %q, want no-cache", got.CacheControl)
	}
}

func TestFlagsUsesThePublicIPBudget(t *testing.T) {
	limiter := &recordingLimiter{allow: true}
	source := &fakeFlagSource{}
	base := newFlagsEnv(t, source, limiter)

	got := send(t, base, http.MethodGet, routeFlags, "", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d", got.Status)
	}
	wantKey := ratelimit.KeyForIP("127.0.0.1", routeFlags)
	if len(limiter.keys) != 1 || limiter.keys[0] != wantKey {
		t.Fatalf("limiter keys = %v, want %q", limiter.keys, wantKey)
	}
	if len(limiter.policies) != 1 || limiter.policies[0] != domain.IPRoutePolicy(routeFlags, domain.OrgRouteLimit) {
		t.Fatalf("policies = %+v", limiter.policies)
	}
}
