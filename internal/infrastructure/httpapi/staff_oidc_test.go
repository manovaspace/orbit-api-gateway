package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ids"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/memory"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/staffoidc"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
)

const (
	testIssuer   = "https://identity.test/realms/staff"
	testAudience = "falak-console"
	testHS256    = "staff-oidc-test-hs256-secret"
)

var testStart = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// fakeClock is the verifier's and the test's shared time source.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// jwksServer serves a mutable JWK set, as the Keycloak certs endpoint does.
type jwksServer struct {
	*httptest.Server
	mu   sync.Mutex
	body []byte
}

func newJWKSServer(t *testing.T, keys map[string]*rsa.PublicKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.set(keys)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		body := s.body
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

// set replaces the served key set.
func (s *jwksServer) set(keys map[string]*rsa.PublicKey) {
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	for kid, pub := range keys {
		doc.Keys = append(doc.Keys, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	body, _ := json.Marshal(doc)
	s.mu.Lock()
	s.body = body
	s.mu.Unlock()
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

// keycloakClaims returns a valid staff access token body at the test clock time.
func keycloakClaims(clock *fakeClock, groups ...string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                issuerClaim(),
		"sub":                "user-1",
		"aud":                "account",
		"azp":                testAudience,
		"preferred_username": "dana",
		"email":              "dana@manova.test",
		"groups":             groups,
		"iat":                clock.Now().Unix(),
		"exp":                clock.Now().Add(5 * time.Minute).Unix(),
	}
}

func issuerClaim() string { return testIssuer }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return signed
}

// oidcFixture wires a verifier to a JWKS server and a token middleware.
type oidcFixture struct {
	clock  *fakeClock
	jwks   *jwksServer
	key    *rsa.PrivateKey
	tokens *TokenAuth
}

func newOIDCFixture(t *testing.T, svc *application.Service, hs256Disabled bool) *oidcFixture {
	t.Helper()
	clock := &fakeClock{now: testStart}
	key := newRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	verifier, err := staffoidc.New(staffoidc.Config{
		Issuer:        testIssuer,
		Audience:      testAudience,
		AllowedGroups: []string{"dev", "admins"},
		JWKSURL:       jwks.URL,
		Clock:         clock,
	})
	if err != nil {
		t.Fatalf("staffoidc.New: %v", err)
	}
	if svc == nil {
		svc = application.NewService(application.Deps{})
	}
	tokens := NewTokenAuth(svc, testHS256).
		WithStaffOIDC(verifier).
		WithStaffHS256Disabled(hs256Disabled)
	return &oidcFixture{clock: clock, jwks: jwks, key: key, tokens: tokens}
}

// staffProbe records the staff context a request reached.
type staffProbe struct {
	called       bool
	subject      string
	isStaff      bool
	breakGlass   bool
	reason       string
	targetOrg    string
	userID       string
	identityFlag bool
}

func (p *staffProbe) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p.called = true
		p.subject = StaffSubjectFromContext(ctx)
		p.isStaff = IsStaffFromContext(ctx)
		p.breakGlass = BreakGlassFromContext(ctx)
		p.reason = BreakGlassReasonFromContext(ctx)
		p.targetOrg = TargetOrgFromContext(ctx)
		p.userID = UserIDFromContext(ctx)
		_, p.identityFlag = StaffIdentityFromContext(ctx)
		w.WriteHeader(http.StatusOK)
	})
}

func doStaff(t *testing.T, handler http.Handler, method, token string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/staff/inspect/org-acme", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestKeycloakStaffTokenAcceptedWithAllowedGroup(t *testing.T) {
	f := newOIDCFixture(t, nil, false)
	probe := &staffProbe{}
	handler := f.tokens.RequireStaff(probe.handler())

	// "/dev" with a leading slash matches the allowed group "dev".
	claims := keycloakClaims(f.clock, "/dev")
	claims["org"] = "claimed-org" // must be ignored: the target org comes from the header
	claims["break_glass"] = true  // must be ignored too
	token := signRS256(t, f.key, "kid-1", claims)

	rec := doStaff(t, handler, http.MethodPost, token, map[string]string{
		"X-Staff-Reason":     "INC-900 tenant support",
		"X-Staff-Target-Org": "org-acme",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !probe.called || !probe.isStaff || !probe.identityFlag {
		t.Fatalf("staff context not set: %+v", probe)
	}
	if probe.subject != "keycloak:user-1" || probe.userID != "keycloak:user-1" {
		t.Fatalf("subject = %q user = %q, want keycloak:user-1", probe.subject, probe.userID)
	}
	if probe.reason != "INC-900 tenant support" {
		t.Fatalf("reason = %q", probe.reason)
	}
	if probe.targetOrg != "org-acme" {
		t.Fatalf("target org = %q, want org-acme from header", probe.targetOrg)
	}
	if !probe.breakGlass {
		t.Fatal("break glass should be true when a target org is supplied")
	}
}

func TestKeycloakStaffGroupWithoutLeadingSlash(t *testing.T) {
	f := newOIDCFixture(t, nil, false)
	probe := &staffProbe{}
	handler := f.tokens.RequireStaff(probe.handler())
	token := signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "admins"))
	if rec := doStaff(t, handler, http.MethodGet, token, nil); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestKeycloakStaffRejections(t *testing.T) {
	tests := []struct {
		name       string
		build      func(f *oidcFixture) string
		wantStatus int
	}{
		{
			name: "wrong issuer",
			build: func(f *oidcFixture) string {
				c := keycloakClaims(f.clock, "dev")
				c["iss"] = "https://evil.test/realms/staff"
				return signRS256(t, f.key, "kid-1", c)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "wrong audience",
			build: func(f *oidcFixture) string {
				c := keycloakClaims(f.clock, "dev")
				c["aud"] = []string{"account", "other-console"}
				c["azp"] = "other-console"
				return signRS256(t, f.key, "kid-1", c)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "expired",
			build: func(f *oidcFixture) string {
				c := keycloakClaims(f.clock, "dev")
				c["exp"] = f.clock.Now().Add(-2 * time.Minute).Unix()
				return signRS256(t, f.key, "kid-1", c)
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "missing group",
			build: func(f *oidcFixture) string {
				return signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "sales"))
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "no groups claim",
			build: func(f *oidcFixture) string {
				c := keycloakClaims(f.clock)
				delete(c, "groups")
				return signRS256(t, f.key, "kid-1", c)
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "alg none",
			build: func(f *oidcFixture) string {
				token := jwt.NewWithClaims(jwt.SigningMethodNone, keycloakClaims(f.clock, "dev"))
				signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none: %v", err)
				}
				return signed
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "unknown kid, key not in JWKS",
			build: func(f *oidcFixture) string {
				other := newRSAKey(t)
				return signRS256(t, other, "kid-unknown", keycloakClaims(f.clock, "dev"))
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "signed with a key that does not match the kid",
			build: func(f *oidcFixture) string {
				other := newRSAKey(t)
				return signRS256(t, other, "kid-1", keycloakClaims(f.clock, "dev"))
			},
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newOIDCFixture(t, nil, false)
			probe := &staffProbe{}
			handler := f.tokens.RequireStaff(probe.handler())
			rec := doStaff(t, handler, http.MethodGet, tc.build(f), nil)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if probe.called {
				t.Fatal("inner handler must not run")
			}
		})
	}
}

func TestKeycloakUnknownKidRefetchesAfterRotation(t *testing.T) {
	f := newOIDCFixture(t, nil, false)
	probe := &staffProbe{}
	handler := f.tokens.RequireStaff(probe.handler())

	if rec := doStaff(t, handler, http.MethodGet, signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "dev")), nil); rec.Code != http.StatusOK {
		t.Fatalf("initial status = %d, want 200", rec.Code)
	}

	// The IdP rotates: kid-2 replaces kid-1.
	rotated := newRSAKey(t)
	f.jwks.set(map[string]*rsa.PublicKey{"kid-2": &rotated.PublicKey})
	newToken := signRS256(t, rotated, "kid-2", keycloakClaims(f.clock, "dev"))

	// Within 30 seconds of the last fetch the refetch is refused.
	if rec := doStaff(t, handler, http.MethodGet, newToken, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("throttled status = %d, want 401", rec.Code)
	}

	// After 30 seconds the unknown kid triggers one refetch and succeeds.
	f.clock.Advance(31 * time.Second)
	if rec := doStaff(t, handler, http.MethodGet, newToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("rotated status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestKeycloakJWKSServerDown(t *testing.T) {
	clock := &fakeClock{now: testStart}
	key := newRSAKey(t)
	down := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &key.PublicKey})
	url := down.URL
	down.Close()

	verifier, err := staffoidc.New(staffoidc.Config{
		Issuer:        testIssuer,
		Audience:      testAudience,
		AllowedGroups: []string{"dev"},
		JWKSURL:       url,
		Clock:         clock,
	})
	if err != nil {
		t.Fatalf("staffoidc.New: %v", err)
	}
	tokens := NewTokenAuth(application.NewService(application.Deps{}), testHS256).WithStaffOIDC(verifier)
	probe := &staffProbe{}
	handler := tokens.RequireStaff(probe.handler())

	rec := doStaff(t, handler, http.MethodGet, signRS256(t, key, "kid-1", keycloakClaims(clock, "dev")), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if probe.called {
		t.Fatal("inner handler must not run when JWKS is unreachable")
	}
}

func TestKeycloakStaffWriteRequiresReason(t *testing.T) {
	f := newOIDCFixture(t, nil, false)
	probe := &staffProbe{}
	handler := f.tokens.RequireStaff(probe.handler())
	token := signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "dev"))

	rec := doStaff(t, handler, http.MethodPost, token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST without reason status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "staff reason required") {
		t.Fatalf("body = %s, want staff reason required", rec.Body.String())
	}

	blank := doStaff(t, handler, http.MethodDelete, token, map[string]string{"X-Staff-Reason": "   "})
	if blank.Code != http.StatusBadRequest {
		t.Fatalf("DELETE with blank reason status = %d, want 400", blank.Code)
	}
	if probe.called {
		t.Fatal("inner handler must not run without a reason")
	}

	read := doStaff(t, handler, http.MethodGet, token, nil)
	if read.Code != http.StatusOK {
		t.Fatalf("GET without reason status = %d, want 200", read.Code)
	}
}

func TestKeycloakStaffAuditRecordsReason(t *testing.T) {
	auditStore := memory.NewAuditStore()
	svc := application.NewService(application.Deps{Audit: auditStore, Codes: ids.New()})
	f := newOIDCFixture(t, svc, false)
	handler := f.tokens.RequireStaff(f.tokens.AuditHook(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	token := signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "dev"))

	rec := doStaff(t, handler, http.MethodPost, token, map[string]string{
		"X-Staff-Reason":     "INC-901 restore",
		"X-Staff-Target-Org": "org-acme",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	entries, err := auditStore.ListByOrg(context.Background(), "org-acme")
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %d err = %v, want 1", len(entries), err)
	}
	got := entries[0]
	if got.Actor != "keycloak:user-1" || got.ActorType != "staff" || !got.IsStaff || !got.BreakGlass {
		t.Fatalf("audit entry = %+v", got)
	}
	if got.Reason != "INC-901 restore" {
		t.Fatalf("audit reason = %q", got.Reason)
	}
}

func TestStaffHS256DisabledRefusesHS256Staff(t *testing.T) {
	staffClaims := jwt.MapClaims{
		"sub":           "staff-legacy",
		"staff_subject": "staff-legacy",
		"is_staff":      true,
		"exp":           testStart.Add(time.Hour).Unix(),
	}
	legacy := signTestJWT(t, staffClaims, testHS256)

	f := newOIDCFixture(t, nil, true)
	probe := &staffProbe{}
	handler := f.tokens.RequireStaff(probe.handler())
	if rec := doStaff(t, handler, http.MethodGet, legacy, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("RequireStaff HS256 with disabled = %d, want 401", rec.Code)
	}

	// The tenant routes must not carry a legacy staff token into staff context either.
	dual := f.tokens.Dual(probe.handler())
	if rec := doStaff(t, dual, http.MethodGet, legacy, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Dual HS256 staff with disabled = %d, want 401", rec.Code)
	}
	if probe.called {
		t.Fatal("inner handler must not run for a disabled HS256 staff token")
	}

	// Keycloak tokens still pass.
	token := signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "dev"))
	if rec := doStaff(t, handler, http.MethodGet, token, nil); rec.Code != http.StatusOK {
		t.Fatalf("Keycloak with HS256 disabled = %d, want 200", rec.Code)
	}
}

func TestStaffHS256EnabledByDefault(t *testing.T) {
	legacy := signTestJWT(t, jwt.MapClaims{
		"sub":           "staff-legacy",
		"staff_subject": "staff-legacy",
		"is_staff":      true,
		"exp":           time.Now().Add(time.Hour).Unix(),
	}, testHS256)
	tokens := NewTokenAuth(application.NewService(application.Deps{}), testHS256)
	probe := &staffProbe{}
	if rec := doStaff(t, tokens.RequireStaff(probe.handler()), http.MethodGet, legacy, nil); rec.Code != http.StatusOK {
		t.Fatalf("HS256 staff default = %d, want 200", rec.Code)
	}
	if probe.subject != "staff-legacy" {
		t.Fatalf("subject = %q, want staff-legacy", probe.subject)
	}
}

func TestTenantTokenStillForbiddenOnStaffRoutes(t *testing.T) {
	f := newOIDCFixture(t, nil, false)
	tenant := signTestJWT(t, jwt.MapClaims{
		"sub":      "tenant-admin-alice",
		"org":      "org-acme",
		"is_staff": false,
		"exp":      time.Now().Add(time.Hour).Unix(),
	}, testHS256)
	probe := &staffProbe{}
	rec := doStaff(t, f.tokens.RequireStaff(probe.handler()), http.MethodGet, tenant, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant token status = %d, want 403", rec.Code)
	}
	if probe.called {
		t.Fatal("inner handler must not run for a tenant token")
	}
}

func TestKeycloakStaffRateLimitedPerSubject(t *testing.T) {
	svc := application.NewService(application.Deps{
		Limiter: ratelimit.New(ratelimiting.NewMemoryLimiter()),
	})
	f := newOIDCFixture(t, svc, false)
	handler := f.tokens.RequireStaff(f.tokens.StaffRateLimit(domain.ClassAuthRefresh, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	first := doStaff(t, handler, http.MethodGet, signRS256(t, f.key, "kid-1", keycloakClaims(f.clock, "dev")), nil)
	if first.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", first.Code)
	}
	if first.Header().Get("X-RateLimit-Limit") == "" {
		t.Fatal("staff request should carry rate-limit headers")
	}

	// A different staff subject has its own bucket.
	other := keycloakClaims(f.clock, "dev")
	other["sub"] = "user-2"
	second := doStaff(t, handler, http.MethodGet, signRS256(t, f.key, "kid-1", other), nil)
	if second.Code != http.StatusOK {
		t.Fatalf("other subject status = %d, want 200", second.Code)
	}
	if second.Header().Get("X-RateLimit-Remaining") != first.Header().Get("X-RateLimit-Remaining") {
		t.Fatalf("buckets should be independent: %q vs %q",
			second.Header().Get("X-RateLimit-Remaining"), first.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestStaffOIDCVerifierFailsClosedWithoutGroups(t *testing.T) {
	verifier, err := staffoidc.New(staffoidc.Config{Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("staffoidc.New: %v", err)
	}
	key := newRSAKey(t)
	_, err = verifier.Verify(context.Background(), signRS256(t, key, "kid-1", keycloakClaims(&fakeClock{now: testStart}, "dev")))
	if err == nil {
		t.Fatal("verifier with no allowed groups must refuse every token")
	}
}

func TestStaffOIDCConfigRequiresIssuerAndAudience(t *testing.T) {
	if _, err := staffoidc.New(staffoidc.Config{Audience: testAudience}); err == nil {
		t.Fatal("missing issuer must be an error")
	}
	if _, err := staffoidc.New(staffoidc.Config{Issuer: testIssuer}); err == nil {
		t.Fatal("missing audience must be an error")
	}
}
