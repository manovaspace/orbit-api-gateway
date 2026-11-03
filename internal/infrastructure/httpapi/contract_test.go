package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	orbittoken "github.com/manovaspace/orbit-auth/token"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// This file is the HTTP contract of orbit-api-gateway, captured from the
// net/http server before the Fiber v3 migration. Every assertion below passed
// against that server unchanged. The helpers it calls live in
// contract_harness_test.go; only those helpers changed when the server moved to
// Fiber v3. Do not edit an expectation here to match new behaviour: a difference
// is a contract change and needs the owner.

type response struct {
	Status       int
	ContentType  string
	CacheControl string
	Nosniff      string
	Allow        string
	RetryAfter   string
	RateLimit    string // "limit/remaining", empty when the header is absent
	ResetSet     bool
	Body         string
}

func TestContractInstallerRoutes(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantType   string
		wantCache  string
		wantAllow  string
		wantDigest string
		wantBody   string
	}{
		{
			name: "GET / serves the installer", method: http.MethodGet, path: "/",
			wantStatus: http.StatusOK, wantType: "text/x-shellscript; charset=utf-8",
			wantCache: "no-cache, no-store, must-revalidate", wantDigest: installerDigest,
		},
		{
			name: "query string is accepted", method: http.MethodGet, path: "/?channel=test",
			wantStatus: http.StatusOK, wantType: "text/x-shellscript; charset=utf-8",
			wantCache: "no-cache, no-store, must-revalidate", wantDigest: installerDigest,
		},
		{
			name: "HEAD / has no body", method: http.MethodHead, path: "/",
			wantStatus: http.StatusOK, wantType: "text/x-shellscript; charset=utf-8",
			wantCache: "no-cache, no-store, must-revalidate", wantBody: "",
		},
		{
			name: "POST / is not allowed", method: http.MethodPost, path: "/",
			wantStatus: http.StatusMethodNotAllowed, wantType: "text/plain; charset=utf-8",
			wantAllow: "GET, HEAD", wantBody: "Method Not Allowed\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := send(t, env.main, tc.method, tc.path, "", nil)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.ContentType != tc.wantType {
				t.Fatalf("content-type = %q, want %q", got.ContentType, tc.wantType)
			}
			if got.CacheControl != tc.wantCache {
				t.Fatalf("cache-control = %q, want %q", got.CacheControl, tc.wantCache)
			}
			if got.Allow != tc.wantAllow {
				t.Fatalf("allow = %q, want %q", got.Allow, tc.wantAllow)
			}
			if tc.wantBody != "" && got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
			if tc.wantDigest != "" && digestOf(got.Body) != tc.wantDigest {
				t.Fatalf("body digest = %s, want %s", digestOf(got.Body), tc.wantDigest)
			}
		})
	}
}

func TestContractHealthRoutes(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	t.Run("main /healthz", func(t *testing.T) {
		got := send(t, env.main, http.MethodGet, "/healthz", "", nil)
		if got.Status != http.StatusOK || got.Body != "ok" {
			t.Fatalf("got %d %q, want 200 %q", got.Status, got.Body, "ok")
		}
		if got.ContentType != "text/plain; charset=utf-8" {
			t.Fatalf("content-type = %q", got.ContentType)
		}
	})

	t.Run("main /readyz is not mounted", func(t *testing.T) {
		got := send(t, env.main, http.MethodGet, "/readyz", "", nil)
		if got.Status != http.StatusNotFound || got.Body != "404 page not found\n" {
			t.Fatalf("got %d %q", got.Status, got.Body)
		}
	})

	healthTests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		{"live", http.MethodGet, "/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"ready", http.MethodGet, "/readyz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"post is served", http.MethodPost, "/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"unmapped", http.MethodGet, "/metrics", http.StatusNotFound, "404 page not found\n"},
	}
	for _, tc := range healthTests {
		t.Run("health port "+tc.name, func(t *testing.T) {
			got := send(t, env.health, tc.method, tc.path, "", nil)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.ContentType != "application/json" && got.Status != http.StatusNotFound {
				t.Fatalf("content-type = %q", got.ContentType)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
		})
	}
}

func TestContractUnknownRoutes(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantType   string
		wantAllow  string
		wantBody   string
		wantNosnif bool
	}{
		{name: "GET unknown", method: http.MethodGet, path: "/api/v1/nonexistent", wantStatus: http.StatusNotFound, wantType: "text/plain; charset=utf-8", wantBody: "404 page not found\n", wantNosnif: true},
		{name: "GET install path", method: http.MethodGet, path: "/install", wantStatus: http.StatusNotFound, wantType: "text/plain; charset=utf-8", wantBody: "404 page not found\n", wantNosnif: true},
		{name: "POST unknown", method: http.MethodPost, path: "/unknown", wantStatus: http.StatusMethodNotAllowed, wantType: "text/plain; charset=utf-8", wantAllow: "GET, HEAD", wantBody: "Method Not Allowed\n", wantNosnif: true},
		{name: "PUT root", method: http.MethodPut, path: "/", wantStatus: http.StatusMethodNotAllowed, wantType: "text/plain; charset=utf-8", wantAllow: "GET, HEAD", wantBody: "Method Not Allowed\n", wantNosnif: true},
		{name: "trailing slash", method: http.MethodGet, path: "/api/v1/openapi/gateway.yaml/", wantStatus: http.StatusNotFound, wantType: "text/plain; charset=utf-8", wantBody: "404 page not found\n", wantNosnif: true},
		{name: "GET on a POST route", method: http.MethodGet, path: "/api/v1/auth/login", wantStatus: http.StatusNotFound, wantType: "text/plain; charset=utf-8", wantBody: "404 page not found\n", wantNosnif: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := send(t, env.main, tc.method, tc.path, "", nil)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.ContentType != tc.wantType {
				t.Fatalf("content-type = %q, want %q", got.ContentType, tc.wantType)
			}
			if got.Allow != tc.wantAllow {
				t.Fatalf("allow = %q, want %q", got.Allow, tc.wantAllow)
			}
			if tc.wantNosnif && got.Nosniff != "nosniff" {
				t.Fatalf("x-content-type-options = %q, want nosniff", got.Nosniff)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
		})
	}
}

func TestContractOpenAPIRoutes(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	t.Run("missing artifact is a 404", func(t *testing.T) {
		got := send(t, env.main, http.MethodGet, "/api/v1/openapi/gateway.yaml", "", nil)
		if got.Status != http.StatusNotFound || got.Body != "spec not found\n" {
			t.Fatalf("got %d %q, want 404 %q", got.Status, got.Body, "spec not found\n")
		}
		if got.Nosniff != "nosniff" {
			t.Fatalf("x-content-type-options = %q", got.Nosniff)
		}
	})

	t.Chdir(repoRoot(t))

	tests := []struct {
		name     string
		path     string
		wantType string
		wantHash string
	}{
		{"spec", "/api/v1/openapi/gateway.yaml", "application/yaml", specDigest},
		{"manifest", "/api/v1/openapi/manifest.json", "application/json", manifestDigest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := send(t, env.main, http.MethodGet, tc.path, "", nil)
			if got.Status != http.StatusOK {
				t.Fatalf("status = %d, want 200", got.Status)
			}
			if got.ContentType != tc.wantType {
				t.Fatalf("content-type = %q, want %q", got.ContentType, tc.wantType)
			}
			if digestOf(got.Body) != tc.wantHash {
				t.Fatalf("body digest = %s, want %s", digestOf(got.Body), tc.wantHash)
			}
		})
	}
}

func TestContractAuthRoutes(t *testing.T) {
	t.Run("otp request", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request",
			`{"identifier":"person@example.com","channel":"email","correlation_id":"c-1"}`, jsonHeaders())
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != `{"expires_at":"2026-08-30T23:00:00Z"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.ContentType != "application/json" {
			t.Fatalf("content-type = %q", got.ContentType)
		}
		if got.RateLimit != "3/2" || !got.ResetSet {
			t.Fatalf("identifier rate-limit headers = %q reset=%v", got.RateLimit, got.ResetSet)
		}
	})

	t.Run("otp request falls back to email", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request",
			`{"email":"legacy@example.com","channel":"email"}`, nil)
		if got.Status != http.StatusOK || got.Body != `{"expires_at":"2026-08-30T23:00:00Z"}`+"\n" {
			t.Fatalf("got %d %q", got.Status, got.Body)
		}
		if got.RateLimit != "3/2" {
			t.Fatalf("identifier rate-limit headers = %q, want 3/2", got.RateLimit)
		}
	})

	t.Run("otp request without identifier has no identifier headers", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request", `{"channel":"email"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d", got.Status)
		}
		if got.RateLimit != "5/4" {
			t.Fatalf("rate-limit headers = %q, want the class bucket 5/4", got.RateLimit)
		}
	})

	t.Run("otp verify", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/verify",
			`{"identifier":"person@example.com","code":"123456"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != `{"access_token":"access","expires_at":"2026-08-30T23:00:00Z","refresh_token":"refresh"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.RateLimit != "20/19" {
			t.Fatalf("class rate-limit headers = %q, want 20/19", got.RateLimit)
		}
	})

	t.Run("login", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
			`{"identifier":"+989121234567","password":"correct"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != `{"access_token":"access","expires_at":"2026-08-30T23:00:00Z","refresh_token":"refresh"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.RateLimit != "10/9" {
			t.Fatalf("class rate-limit headers = %q, want 10/9", got.RateLimit)
		}
	})

	t.Run("login with legacy email field", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
			`{"email":"legacy@example.com","password":"correct"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
	})

	t.Run("refresh", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/token/refresh",
			`{"refresh_token":"valid"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != `{"access_token":"access2","expires_at":"2026-08-30T23:00:00Z","refresh_token":"refresh2"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.RateLimit != "30/29" {
			t.Fatalf("class rate-limit headers = %q, want 30/29", got.RateLimit)
		}
	})

	errorTests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{"invalid argument", "/api/v1/auth/otp/request", `{"identifier":"invalid"}`, http.StatusBadRequest, `{"error":"bad identifier"}` + "\n"},
		{"unauthenticated", "/api/v1/auth/otp/request", `{"identifier":"unauth"}`, http.StatusUnauthorized, `{"error":"bad token"}` + "\n"},
		{"permission denied", "/api/v1/auth/otp/request", `{"identifier":"denied"}`, http.StatusForbidden, `{"error":"no"}` + "\n"},
		{"failed precondition", "/api/v1/auth/otp/request", `{"identifier":"precond"}`, http.StatusPreconditionFailed, `{"error":"missing"}` + "\n"},
		{"resource exhausted", "/api/v1/auth/otp/request", `{"identifier":"exhausted"}`, http.StatusTooManyRequests, `{"error":"slow down"}` + "\n"},
		{"unknown upstream error", "/api/v1/auth/otp/request", `{"identifier":"plain"}`, http.StatusInternalServerError, `{"error":"upstream error"}` + "\n"},
		{"verify failure", "/api/v1/auth/otp/verify", `{"identifier":"person@example.com","code":"000000"}`, http.StatusInternalServerError, `{"error":"upstream error"}` + "\n"},
		{"login failure", "/api/v1/auth/login", `{"identifier":"person@example.com","password":"wrong"}`, http.StatusUnauthorized, `{"error":"bad credentials"}` + "\n"},
		{"refresh failure", "/api/v1/auth/token/refresh", `{"refresh_token":"nope"}`, http.StatusInternalServerError, `{"error":"upstream error"}` + "\n"},
		{"invalid json", "/api/v1/auth/login", `not json`, http.StatusBadRequest, `{"error":"invalid json"}` + "\n"},
		{"empty body", "/api/v1/auth/login", ``, http.StatusBadRequest, `{"error":"invalid json"}` + "\n"},
	}
	for _, tc := range errorTests {
		t.Run(tc.name, func(t *testing.T) {
			env := newContractEnv(t, contractConfig{})
			got := send(t, env.main, http.MethodPost, tc.path, tc.body, nil)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.ContentType != "application/json" {
				t.Fatalf("content-type = %q", got.ContentType)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
		})
	}
}

func TestContractBodySizeCap(t *testing.T) {
	// maxAuthBody is the documented cap: one byte over is rejected as invalid
	// JSON, exactly at the cap the body is accepted.
	build := func(n int) string {
		return `{"identifier":"` + strings.Repeat("a", n-17) + `"}`
	}

	t.Run("exactly at the cap", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		body := build(64 << 10)
		if len(body) != 64<<10 {
			t.Fatalf("test body length = %d", len(body))
		}
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request", body, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
	})

	t.Run("one byte over the cap", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		body := build(64<<10 + 1)
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request", body, nil)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got.Status)
		}
		if got.Body != `{"error":"invalid json"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})

	t.Run("a body far over the cap is still rejected", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/login", build(512<<10), nil)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got.Status)
		}
		if got.Body != `{"error":"invalid json"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})
}

func TestContractAuthClassRateLimit(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	var last response
	for i := 0; i < 10; i++ {
		last = send(t, env.main, http.MethodPost, "/api/v1/auth/login",
			`{"identifier":"person@example.com","password":"wrong"}`, nil)
		if last.Status != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d, want 401", i+1, last.Status)
		}
	}
	if last.RateLimit != "10/0" {
		t.Fatalf("allowed response rate limit = %q, want 10/0", last.RateLimit)
	}

	got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
		`{"identifier":"person@example.com","password":"wrong"}`, nil)
	if got.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got.Status)
	}
	if got.Body != `{"error":"rate limit exceeded"}`+"\n" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.RateLimit != "10/0" {
		t.Fatalf("rate limit headers = %q, want 10/0", got.RateLimit)
	}
	if got.RetryAfter == "" {
		t.Fatal("retry-after is missing")
	}
}

func TestContractIdentifierRateLimit(t *testing.T) {
	env := newContractEnv(t, contractConfig{})

	for i := 0; i < 3; i++ {
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request",
			`{"identifier":"limit@example.com"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, got.Status)
		}
	}
	got := send(t, env.main, http.MethodPost, "/api/v1/auth/otp/request",
		`{"identifier":"limit@example.com"}`, nil)
	if got.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got.Status)
	}
	if got.Body != `{"error":"rate limit exceeded"}`+"\n" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.RateLimit != "3/0" {
		t.Fatalf("rate limit headers = %q, want 3/0", got.RateLimit)
	}
	if got.RetryAfter == "" {
		t.Fatal("retry-after is missing")
	}
}

func TestContractLimiterUnavailable(t *testing.T) {
	env := newContractEnv(t, contractConfig{failingLimiter: true})

	for _, tc := range []struct {
		name string
		path string
		body string
	}{
		{"class limit", "/api/v1/auth/login", `{"identifier":"person@example.com","password":"correct"}`},
		{"identifier limit", "/api/v1/auth/otp/request", `{"identifier":"person@example.com"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := send(t, env.main, http.MethodPost, tc.path, tc.body, nil)
			if got.Status != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", got.Status)
			}
			if got.Body != `{"error":"rate limiter unavailable"}`+"\n" {
				t.Fatalf("body = %q", got.Body)
			}
			if got.RetryAfter != "5" {
				t.Fatalf("retry-after = %q, want 5", got.RetryAfter)
			}
			if got.RateLimit != "" {
				t.Fatalf("rate limit headers = %q, want none", got.RateLimit)
			}
		})
	}
}

func TestContractTrustProxyHeaderForwarding(t *testing.T) {
	t.Run("trusted proxy separates clients", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{trustProxy: true})
		for i := 0; i < 10; i++ {
			got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
				`{"identifier":"person@example.com","password":"wrong"}`,
				map[string]string{"X-Forwarded-For": "203.0.113.1"})
			if got.Status != http.StatusUnauthorized {
				t.Fatalf("request %d status = %d", i+1, got.Status)
			}
		}
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
			`{"identifier":"person@example.com","password":"wrong"}`,
			map[string]string{"X-Forwarded-For": "203.0.113.2"})
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("a second forwarded client got %d, want 401", got.Status)
		}
	})

	t.Run("untrusted proxy ignores the header", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		for i := 0; i < 10; i++ {
			got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
				`{"identifier":"person@example.com","password":"wrong"}`,
				map[string]string{"X-Forwarded-For": "203.0.113.1"})
			if got.Status != http.StatusUnauthorized {
				t.Fatalf("request %d status = %d", i+1, got.Status)
			}
		}
		got := send(t, env.main, http.MethodPost, "/api/v1/auth/login",
			`{"identifier":"person@example.com","password":"wrong"}`,
			map[string]string{"X-Forwarded-For": "203.0.113.2"})
		if got.Status != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", got.Status)
		}
	})
}

func TestContractOwnershipRoutes(t *testing.T) {
	t.Run("challenge", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/challenge",
			`{"email":"Owner@Example.com","display_name":"Owner"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != `{"status":"challenge_dispatched","expires_in":"10m"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.RateLimit != "3/2" {
			t.Fatalf("rate limit headers = %q, want 3/2", got.RateLimit)
		}
	})

	t.Run("challenge rejects a bad email", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/challenge",
			`{"email":"not-an-email"}`, nil)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got.Status)
		}
		if got.Body != `{"error":"valid email is required"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})

	t.Run("challenge alias", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/admin/challenge",
			`{"email":"alias@example.com"}`, nil)
		if got.Status != http.StatusOK || got.Body != `{"status":"challenge_dispatched","expires_in":"10m"}`+"\n" {
			t.Fatalf("got %d %q", got.Status, got.Body)
		}
	})

	t.Run("verify unknown challenge", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
			`{"email":"nobody@example.com","code":"123456"}`, nil)
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got.Status)
		}
		if got.Body != `{"error":"invalid or expired verification code"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})

	t.Run("verify missing fields", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/system/ownership/verify",
			`{"email":"","code":""}`, nil)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got.Status)
		}
		if got.Body != `{"error":"email and code are required"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})

	t.Run("verify alias", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/admin/verify",
			`{"email":"nobody@example.com","code":"123456"}`, nil)
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got.Status)
		}
	})
}

func TestContractOnboardingRoutes(t *testing.T) {
	claim := `{"invite_token":"tok-1","desired_uid":"john","email":"john@example.com","display_name":"John Doe","ssh_public_key":"ssh-ed25519 AAAA john","machine_fingerprint":"fp-1"}`

	t.Run("claim", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/dev/onboard/claim", claim,
			map[string]string{"Idempotency-Key": "idem-1"})
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.ContentType != "application/json" {
			t.Fatalf("content-type = %q", got.ContentType)
		}
		if got.Body != claimBody {
			t.Fatalf("body = %q\nwant   %q", got.Body, claimBody)
		}
	})

	t.Run("claim replay is idempotent", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		first := send(t, env.main, http.MethodPost, "/api/v1/dev/onboard/claim", claim,
			map[string]string{"Idempotency-Key": "idem-1"})
		if first.Status != http.StatusOK {
			t.Fatalf("first status = %d", first.Status)
		}
		got := send(t, env.main, http.MethodPost, "/api/v1/dev/onboard/claim", claim,
			map[string]string{"Idempotency-Key": "idem-1"})
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != claimReplayBody {
			t.Fatalf("body = %q\nwant   %q", got.Body, claimReplayBody)
		}
	})

	t.Run("claim defaults", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/onboard/claim",
			`{"invite_token":"tok-2","desired_uid":"JANE"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != claimDefaultBody {
			t.Fatalf("body = %q\nwant   %q", got.Body, claimDefaultBody)
		}
	})

	t.Run("claim via the v1 alias", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/v1/onboard/claim",
			`{"invite_token":"tok-3","desired_uid":"bob"}`, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d, want 200", got.Status)
		}
		if got.Body != claimAliasBody {
			t.Fatalf("body = %q\nwant   %q", got.Body, claimAliasBody)
		}
	})

	t.Run("claim requires fields", func(t *testing.T) {
		env := newContractEnv(t, contractConfig{})
		got := send(t, env.main, http.MethodPost, "/api/v1/dev/onboard/claim",
			`{"invite_token":"","desired_uid":""}`, nil)
		if got.Status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", got.Status)
		}
		if got.Body != `{"error":"invite_token and desired_uid are required"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
	})
}

func TestContractJWKS(t *testing.T) {
	env := newContractEnv(t, contractConfig{})
	got := send(t, env.main, http.MethodGet, "/.well-known/jwks.json", "", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("content-type = %q", got.ContentType)
	}
	if got.CacheControl != "public, max-age=300" {
		t.Fatalf("cache-control = %q", got.CacheControl)
	}
	var doc orbittoken.JWKSet
	if err := json.Unmarshal([]byte(got.Body), &doc); err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0].KeyID != "k1" || doc.Keys[0].Alg != "RS256" {
		t.Fatalf("unexpected document: %+v", doc)
	}
	if _, err := doc.KeySet(); err != nil {
		t.Fatalf("document does not round-trip: %v", err)
	}
}

func TestContractJWKSNotConfigured(t *testing.T) {
	env := newContractEnvWithoutJWKS(t)
	got := send(t, env.main, http.MethodGet, "/.well-known/jwks.json", "", nil)
	if got.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", got.Status)
	}
}

func jsonHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/json"}
}

// The digests and bodies below were captured from the running net/http server
// before the Fiber v3 migration.
const (
	installerDigest = "f87e363d4ac3ea888dfe28b4b713fbcf38268ef68226f9c02b4537933dafd926"
	specDigest      = "cf50935f0062539063a5d6be83e99755e39e4e0b103354649919c3b29d2c69db"
	manifestDigest  = "52d4ee360e6f9693c042a1f2e95b0155b8e68f51178d43cd3726a595cd2517a6"

	claimBodyFixture        = `{"status":"provisioned","idempotent_replay":false,"user":{"uid":"john","email":"john@example.com","display_name":"John Doe","groups":["dev","orbit"]},"credentials":{"forgejo_username":"john","forgejo_mcp_token":"%s","wireguard_config":"[Interface]\nPrivateKey = \u003cgenerated-client-key\u003e\nAddress = 10.42.0.53/32\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=\nEndpoint = vpn.internal.manova.space:51820\nAllowedIPs = 10.42.0.0/16, 172.28.0.0/16\nPersistentKeepalive = 25"},"workspace":{"git_remote_base":"ssh://git@git.internal.manova.space:2222/manova","default_manifest_scope":"core"}}` + "\n"
	claimReplayBodyFixture  = `{"status":"provisioned","idempotent_replay":true,"user":{"uid":"john","email":"john@example.com","display_name":"John Doe","groups":["dev","orbit"]},"credentials":{"forgejo_username":"john","forgejo_mcp_token":"%s","wireguard_config":"[Interface]\nPrivateKey = \u003cgenerated-client-key\u003e\nAddress = 10.42.0.53/32\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=\nEndpoint = vpn.internal.manova.space:51820\nAllowedIPs = 10.42.0.0/16, 172.28.0.0/16\nPersistentKeepalive = 25"},"workspace":{"git_remote_base":"ssh://git@git.internal.manova.space:2222/manova","default_manifest_scope":"core"}}` + "\n"
	claimDefaultBodyFixture = `{"status":"provisioned","idempotent_replay":false,"user":{"uid":"jane","email":"jane@manova.space","display_name":"Jane","groups":["dev","orbit"]},"credentials":{"forgejo_username":"jane","forgejo_mcp_token":"%s","wireguard_config":"[Interface]\nPrivateKey = \u003cgenerated-client-key\u003e\nAddress = 10.42.0.162/32\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=\nEndpoint = vpn.internal.manova.space:51820\nAllowedIPs = 10.42.0.0/16, 172.28.0.0/16\nPersistentKeepalive = 25"},"workspace":{"git_remote_base":"ssh://git@git.internal.manova.space:2222/manova","default_manifest_scope":"core"}}` + "\n"
	claimAliasBodyFixture   = `{"status":"provisioned","idempotent_replay":false,"user":{"uid":"bob","email":"bob@manova.space","display_name":"Bob","groups":["dev","orbit"]},"credentials":{"forgejo_username":"bob","forgejo_mcp_token":"%s","wireguard_config":"[Interface]\nPrivateKey = \u003cgenerated-client-key\u003e\nAddress = 10.42.0.158/32\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = 4gZ+examplePublicKeyOrbitGatewayVPNControllerKey=\nEndpoint = vpn.internal.manova.space:51820\nAllowedIPs = 10.42.0.0/16, 172.28.0.0/16\nPersistentKeepalive = 25"},"workspace":{"git_remote_base":"ssh://git@git.internal.manova.space:2222/manova","default_manifest_scope":"core"}}` + "\n"
)

// claimBody and friends are the captured claim responses with the MCP token
// the domain derives for each claim, interpolated at runtime so the fixtures
// never carry a token-shaped literal.
var (
	claimBody        = claimBodyWithToken(claimBodyFixture, "tok-1", "john")
	claimReplayBody  = claimBodyWithToken(claimReplayBodyFixture, "tok-1", "john")
	claimDefaultBody = claimBodyWithToken(claimDefaultBodyFixture, "tok-2", "jane")
	claimAliasBody   = claimBodyWithToken(claimAliasBodyFixture, "tok-3", "bob")
)

func claimBodyWithToken(fixture, inviteToken, uid string) string {
	return fmt.Sprintf(fixture, domain.ClaimCredentialsFor(inviteToken, uid).ForgejoMCPToken)
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}

func digestOf(s string) string { return digestHex(s) }
