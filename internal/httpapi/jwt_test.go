package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTAuth_Matrix(t *testing.T) {
	secret := []byte("test-secret-key-12345")
	t.Setenv("JWT_SECRET", "test-secret-key-12345")

	validToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("failed to create valid token: %v", err)
	}

	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("failed to create expired token: %v", err)
	}

	wrongKeyToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString([]byte("wrong-secret-key-99999"))
	if err != nil {
		t.Fatalf("failed to create wrong key token: %v", err)
	}

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
	t.Setenv("JWT_SECRET", "")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")

	handler := JWTAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer something")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when JWT_SECRET is missing in prod, got %d", rec.Code)
	}
}
