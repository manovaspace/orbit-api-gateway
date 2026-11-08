package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// fakeIdentity is the upstream auth port for the token middleware.
type fakeIdentity struct {
	identities map[string]domain.APIIdentity
}

func (f fakeIdentity) RequestOTP(context.Context, domain.OTPRequest) (string, error) {
	return "", nil
}

func (f fakeIdentity) VerifyOTP(context.Context, domain.OTPVerification) (domain.TokenPair, error) {
	return domain.TokenPair{}, nil
}

func (f fakeIdentity) LoginWithPassword(context.Context, domain.PasswordLogin) (domain.TokenPair, error) {
	return domain.TokenPair{}, nil
}

func (f fakeIdentity) RefreshToken(context.Context, string) (domain.TokenPair, error) {
	return domain.TokenPair{}, nil
}

func (f fakeIdentity) RevokeRefreshToken(context.Context, string) error {
	return nil
}

func (f fakeIdentity) ValidateAPIToken(_ context.Context, secret string) (domain.APIIdentity, error) {
	identity, ok := f.identities[secret]
	if !ok {
		return domain.APIIdentity{}, domain.NewError(domain.KindUnauthenticated, "invalid token")
	}
	return identity, nil
}

// tokenService wraps the identity fake in the application service the
// middleware calls.
func tokenService(auth domain.AuthService) *application.Service {
	return application.NewService(application.Deps{Auth: auth})
}

func TestTokenAuthDualScopes(t *testing.T) {
	auth := fakeIdentity{identities: map[string]domain.APIIdentity{
		"oat_read_only":   {UserID: "user-read", Scopes: []string{"read"}},
		"oat_write_only":  {UserID: "user-write", Scopes: []string{"write"}},
		"oat_read_write":  {UserID: "user-read-write", Scopes: []string{"read", "write"}},
		"oat_empty_scope": {UserID: "user-legacy", Scopes: []string{}},
	}}
	tokens := NewTokenAuth(tokenService(auth), "test-secret-dual-auth")

	tests := []struct {
		name         string
		method       string
		token        string
		wantStatus   int
		wantUserID   string
		expectCalled bool
	}{
		{"GET with read scope", http.MethodGet, "oat_read_only", http.StatusOK, "user-read", true},
		{"POST with read scope", http.MethodPost, "oat_read_only", http.StatusForbidden, "", false},
		{"POST with write scope", http.MethodPost, "oat_write_only", http.StatusOK, "user-write", true},
		{"GET with write scope", http.MethodGet, "oat_write_only", http.StatusOK, "user-write", true},
		{"HEAD with read scope", http.MethodHead, "oat_read_only", http.StatusOK, "user-read", true},
		{"OPTIONS with read scope", http.MethodOptions, "oat_read_only", http.StatusOK, "user-read", true},
		{"PUT with read scope", http.MethodPut, "oat_read_only", http.StatusForbidden, "", false},
		{"DELETE with read scope", http.MethodDelete, "oat_read_only", http.StatusForbidden, "", false},
		{"PATCH with write scope", http.MethodPatch, "oat_write_only", http.StatusOK, "user-write", true},
		{"legacy token GET", http.MethodGet, "oat_empty_scope", http.StatusOK, "user-legacy", true},
		{"legacy token POST", http.MethodPost, "oat_empty_scope", http.StatusOK, "user-legacy", true},
		{"unknown api token", http.MethodGet, "oat_nonexistent", http.StatusUnauthorized, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotUserID, gotHeader string
			handler := tokens.Dual(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUserID = UserIDFromContext(r.Context())
				gotHeader = r.Header.Get("X-User-Id")
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(tc.method, "/api/v1/resource", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if called != tc.expectCalled {
				t.Fatalf("inner handler called = %v, want %v", called, tc.expectCalled)
			}
			if !tc.expectCalled {
				return
			}
			if gotUserID != tc.wantUserID || gotHeader != tc.wantUserID {
				t.Fatalf("context user = %q header = %q, want %q", gotUserID, gotHeader, tc.wantUserID)
			}
		})
	}
}

func TestTokenAuthDualJWT(t *testing.T) {
	secret := []byte("test-dual-auth-jwt-secret")
	tokens := NewTokenAuth(tokenService(fakeIdentity{}), "test-dual-auth-jwt-secret")

	sign := func(claims jwt.MapClaims, key []byte) string {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	valid := sign(jwt.MapClaims{"sub": "jwt-user-456", "exp": time.Now().Add(time.Hour).Unix()}, secret)
	expired := sign(jwt.MapClaims{"sub": "jwt-user-456", "exp": time.Now().Add(-time.Hour).Unix()}, secret)
	wrongKey := sign(jwt.MapClaims{"sub": "jwt-user-456", "exp": time.Now().Add(time.Hour).Unix()}, []byte("wrong-key"))

	tests := []struct {
		name       string
		authHeader string
		setHeader  bool
		wantStatus int
	}{
		{"valid jwt", "Bearer " + valid, true, http.StatusOK},
		{"missing header", "", false, http.StatusUnauthorized},
		{"missing bearer prefix", valid, true, http.StatusUnauthorized},
		{"expired jwt", "Bearer " + expired, true, http.StatusUnauthorized},
		{"wrong key", "Bearer " + wrongKey, true, http.StatusUnauthorized},
		{"malformed jwt", "Bearer malformed.jwt", true, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotUserID string
			handler := tokens.Dual(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUserID = UserIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/jwt-protected", nil)
			if tc.setHeader {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK && gotUserID != "jwt-user-456" {
				t.Fatalf("context user = %q", gotUserID)
			}
		})
	}
}

func TestTokenAuthJWTOnly(t *testing.T) {
	secret := []byte("test-jwt-only-secret")
	tokens := NewTokenAuth(tokenService(fakeIdentity{}), "test-jwt-only-secret")

	sign := func(claims jwt.MapClaims, key []byte) string {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	valid := sign(jwt.MapClaims{"sub": "user-123", "exp": time.Now().Add(time.Hour).Unix()}, secret)
	expired := sign(jwt.MapClaims{"sub": "user-123", "exp": time.Now().Add(-time.Hour).Unix()}, secret)
	wrongKey := sign(jwt.MapClaims{"sub": "user-123", "exp": time.Now().Add(time.Hour).Unix()}, []byte("wrong"))

	tests := []struct {
		name       string
		authHeader string
		setHeader  bool
		wantStatus int
	}{
		{"valid token", "Bearer " + valid, true, http.StatusOK},
		{"missing header", "", false, http.StatusUnauthorized},
		{"missing bearer prefix", valid, true, http.StatusUnauthorized},
		{"basic auth", "Basic " + valid, true, http.StatusUnauthorized},
		{"expired token", "Bearer " + expired, true, http.StatusUnauthorized},
		{"wrong key", "Bearer " + wrongKey, true, http.StatusUnauthorized},
		{"malformed token", "Bearer invalid.jwt.token", true, http.StatusUnauthorized},
		{"non-jwt string", "Bearer not_a_jwt_at_all", true, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotUserID, gotHeader string
			handler := tokens.JWT(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUserID = UserIDFromContext(r.Context())
				gotHeader = r.Header.Get("X-User-Id")
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tc.setHeader {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus == http.StatusOK {
				if !called || gotUserID != "user-123" {
					t.Fatalf("called=%v user=%q", called, gotUserID)
				}
				if gotHeader != "" {
					t.Fatalf("JWT middleware set X-User-Id = %q", gotHeader)
				}
				return
			}
			if called {
				t.Fatal("the inner handler ran on a rejected token")
			}
		})
	}
}

func TestTokenAuthFailsClosedWithoutASecret(t *testing.T) {
	tokens := NewTokenAuth(tokenService(fakeIdentity{}), "")

	for name, handler := range map[string]http.Handler{
		"dual": tokens.Dual(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
		"jwt": tokens.JWT(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})),
	} {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer something")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s status = %d, want 500", name, rec.Code)
		}
		if body := rec.Body.String(); body != `{"error":"auth misconfigured"}`+"\n" {
			t.Fatalf("%s body = %q", name, body)
		}
	}
}

func TestScopesAllow(t *testing.T) {
	tests := []struct {
		scopes []string
		method string
		want   bool
	}{
		{nil, http.MethodPost, true},
		{[]string{"read"}, http.MethodGet, true},
		{[]string{" READ "}, http.MethodHead, true},
		{[]string{"read"}, http.MethodPost, false},
		{[]string{"write"}, http.MethodPost, true},
		{[]string{"write"}, http.MethodGet, true},
		{[]string{"admin"}, http.MethodGet, false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, "/", nil)
		if got := scopesAllow(req, tc.scopes); got != tc.want {
			t.Fatalf("scopesAllow(%v, %s) = %v, want %v", tc.scopes, tc.method, got, tc.want)
		}
	}
}
