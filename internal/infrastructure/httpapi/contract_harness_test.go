package httpapi

// This file is the harness the contract in contract_test.go runs on. It is the
// only part of the contract suite that changed when the server moved to Fiber
// v3: the assertions stayed byte-identical.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	orbittoken "github.com/manovaspace/orbit-auth/token"
	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/memory"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

type contractConfig struct {
	trustProxy     bool
	failingLimiter bool
}

type contractEnv struct {
	main   string
	health string
}

// newContractEnv wires the same objects cmd/gateway wires and serves them on
// loopback, so every contract assertion travels the real HTTP stack.
func newContractEnv(t *testing.T, cfg contractConfig) *contractEnv {
	t.Helper()
	return newContractEnvWith(t, cfg, true)
}

func newContractEnvWithoutJWKS(t *testing.T) *contractEnv {
	t.Helper()
	return newContractEnvWith(t, contractConfig{}, false)
}

func newContractEnvWith(t *testing.T, cfg contractConfig, withJWKS bool) *contractEnv {
	t.Helper()

	upstream := startContractUpstream(t)
	client, err := authclient.NewClient(upstream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var limiter domain.Limiter = ratelimit.New(ratelimiting.NewMemoryLimiter())
	if cfg.failingLimiter {
		limiter = failingLimiter{}
	}

	svc := application.NewService(application.Deps{
		Auth:       client,
		Limiter:    limiter,
		Clock:      fixedClock{},
		Codes:      fixedCodes{},
		Challenges: memory.NewChallenges(),
		Claims:     memory.NewClaims(),
		Assets:     assets.New("openapi"),
	})
	srv := New(svc, Options{TrustProxy: cfg.trustProxy, JWTSecret: "contract-secret"})

	if withJWKS {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(orbittoken.KeySet{"k1": &key.PublicKey}.Document())
		if err != nil {
			t.Fatal(err)
		}
		srv.ServeJWKS(body)
	}

	health := NewHealth()
	return &contractEnv{main: serveOnLoopback(t, srv), health: serveOnLoopback(t, health)}
}

// serveOnLoopback starts srv on an ephemeral port and returns its base URL.
func serveOnLoopback(t *testing.T, srv *Server) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.serve(listener)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	return "http://" + listener.Addr().String()
}

// fixedClock and fixedCodes keep the ownership fingerprint and challenge body
// deterministic. The server-side success path is pinned by
// TestOwnershipVerifySuccessThroughTheServer.
type fixedClock struct{}

func (fixedClock) Now() time.Time {
	return time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
}

type fixedCodes struct{}

func (fixedCodes) NewCode() string { return "123456" }

// send performs one real HTTP request and copies only the headers and body the
// contract names. Transport framing (Content-Length, Transfer-Encoding, Date)
// is deliberately excluded: it is not an application contract, and the two
// server implementations frame large bodies differently.
func send(t *testing.T, base, method, path, body string, hdr map[string]string) response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	got := response{
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		CacheControl: resp.Header.Get("Cache-Control"),
		Nosniff:      resp.Header.Get("X-Content-Type-Options"),
		Allow:        resp.Header.Get("Allow"),
		RetryAfter:   resp.Header.Get("Retry-After"),
		Body:         string(payload),
	}
	if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "" {
		got.RateLimit = limit + "/" + resp.Header.Get("X-RateLimit-Remaining")
	}
	if reset := resp.Header.Get("X-RateLimit-Reset"); reset != "" {
		if _, err := strconv.ParseInt(reset, 10, 64); err == nil {
			got.ResetSet = true
		}
	}
	return got
}

func digestHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// failingLimiter makes every rate-limit check fail, which the edge must report
// as 503 with Retry-After: 5 rather than letting the request through.
type failingLimiter struct{}

func (failingLimiter) Allow(context.Context, string, domain.Policy) (domain.Decision, error) {
	return domain.Decision{}, errors.New("limiter down")
}

// contractUpstream is a deterministic stand-in for orbit-auth. Inputs select
// the response, so contract cases stay independent and order-free.
type contractUpstream struct {
	authv1.UnimplementedAuthServiceServer
}

func (contractUpstream) RequestOTP(_ context.Context, in *authv1.RequestOTPRequest) (*authv1.RequestOTPResponse, error) {
	switch in.GetIdentifier() {
	case "invalid":
		return nil, status.Error(codes.InvalidArgument, "bad identifier")
	case "unauth":
		return nil, status.Error(codes.Unauthenticated, "bad token")
	case "denied":
		return nil, status.Error(codes.PermissionDenied, "no")
	case "precond":
		return nil, status.Error(codes.FailedPrecondition, "missing")
	case "exhausted":
		return nil, status.Error(codes.ResourceExhausted, "slow down")
	case "plain":
		return nil, errors.New("boom")
	}
	return &authv1.RequestOTPResponse{ExpiresAt: "2026-08-30T23:00:00Z"}, nil
}

func (contractUpstream) VerifyOTP(_ context.Context, in *authv1.VerifyOTPRequest) (*authv1.VerifyOTPResponse, error) {
	if in.GetCode() != "123456" {
		return nil, errors.New("invalid code")
	}
	return &authv1.VerifyOTPResponse{Tokens: &authv1.TokenResponse{
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    "2026-08-30T23:00:00Z",
	}}, nil
}

func (contractUpstream) LoginWithPassword(_ context.Context, in *authv1.LoginWithPasswordRequest) (*authv1.TokenResponse, error) {
	if in.GetPassword() != "correct" {
		return nil, status.Error(codes.Unauthenticated, "bad credentials")
	}
	return &authv1.TokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: "2026-08-30T23:00:00Z"}, nil
}

func (contractUpstream) RefreshToken(_ context.Context, in *authv1.RefreshTokenRequest) (*authv1.TokenResponse, error) {
	if in.GetRefreshToken() != "valid" {
		return nil, errors.New("invalid refresh token")
	}
	return &authv1.TokenResponse{AccessToken: "access2", RefreshToken: "refresh2", ExpiresAt: "2026-08-30T23:00:00Z"}, nil
}

func (contractUpstream) ValidateApiToken(_ context.Context, in *authv1.ValidateApiTokenRequest) (*authv1.ValidateApiTokenResponse, error) {
	if in.GetSecret() != "oat_ok" {
		return nil, errors.New("invalid token")
	}
	return &authv1.ValidateApiTokenResponse{UserId: "user-1", Scopes: []string{"read", "write"}}, nil
}

func startContractUpstream(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, contractUpstream{})
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)
	return listener.Addr().String()
}
