package httpapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	orbittoken "github.com/manovaspace/orbit-auth/token"
)

var gatewayJWTTestKeyOnce sync.Once
var gatewayJWTTestKey *rsa.PrivateKey
var gatewayJWTTestKeyErr error

func configureJWTTestKeys(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	gatewayJWTTestKeyOnce.Do(func() {
		gatewayJWTTestKey, gatewayJWTTestKeyErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if gatewayJWTTestKeyErr != nil {
		t.Fatal(gatewayJWTTestKeyErr)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&gatewayJWTTestKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "test-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_PUBLIC_KEYS_DIR", directory)
	return gatewayJWTTestKey
}

func signJWTTestToken(t *testing.T, key *rsa.PrivateKey, subject string, expires time.Time) string {
	t.Helper()
	token, err := orbittoken.SignAccessToken(key, "test-key", subject, expires)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestJWTAuth_Matrix(t *testing.T) {
	privateKey := configureJWTTestKeys(t)
	validToken := signJWTTestToken(t, privateKey, "user-123", time.Now().Add(time.Hour))
	expiredToken := signJWTTestToken(t, privateKey, "user-123", time.Now().Add(-time.Hour))
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyToken := signJWTTestToken(t, wrongKey, "user-123", time.Now().Add(time.Hour))

	tests := []struct {
		name           string
		authHeader     string
		setAuthHeader  bool
		expectedStatus int
		expectUserID   string
	}{
		{
			name:           "valid token",
			authHeader:     "Bearer " + validToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusOK,
			expectUserID:   "user-123",
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			setAuthHeader:  false,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "missing bearer prefix",
			authHeader:     validToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "basic auth instead of bearer",
			authHeader:     "Basic " + validToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "expired token",
			authHeader:     "Bearer " + expiredToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "tampered signature / wrong key",
			authHeader:     "Bearer " + wrongKeyToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed token string",
			authHeader:     "Bearer invalid.jwt.token",
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed non-jwt string",
			authHeader:     "Bearer not_a_jwt_at_all",
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotUserID string

			handler := JWTAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUserID = UserIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tc.setAuthHeader {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rec.Code)
			}

			if tc.expectedStatus == http.StatusOK {
				if !called {
					t.Errorf("expected inner handler to be called")
				}
				if gotUserID != tc.expectUserID {
					t.Errorf("expected user ID %q, got %q", tc.expectUserID, gotUserID)
				}
			} else {
				if called {
					t.Errorf("inner handler should not have been called on failure")
				}
			}
		})
	}
}

func TestJWTAuth_MissingSecret(t *testing.T) {
	t.Setenv("JWT_PUBLIC_KEYS_DIR", "")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")

	handler := JWTAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer something")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when JWT public keys are missing in prod, got %d", rec.Code)
	}
}
