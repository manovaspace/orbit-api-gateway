package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
)

type fakeAuthServiceClient struct {
	requestOTPFn        func(ctx context.Context, in *authv1.RequestOTPRequest, opts ...grpc.CallOption) (*authv1.RequestOTPResponse, error)
	verifyOTPFn         func(ctx context.Context, in *authv1.VerifyOTPRequest, opts ...grpc.CallOption) (*authv1.VerifyOTPResponse, error)
	loginWithPasswordFn func(ctx context.Context, in *authv1.LoginWithPasswordRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error)
	refreshTokenFn      func(ctx context.Context, in *authv1.RefreshTokenRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error)
	createApiTokenFn    func(ctx context.Context, in *authv1.CreateApiTokenRequest, opts ...grpc.CallOption) (*authv1.CreateApiTokenResponse, error)
	listApiTokensFn     func(ctx context.Context, in *authv1.ListApiTokensRequest, opts ...grpc.CallOption) (*authv1.ListApiTokensResponse, error)
	revokeApiTokenFn    func(ctx context.Context, in *authv1.RevokeApiTokenRequest, opts ...grpc.CallOption) (*authv1.RevokeApiTokenResponse, error)
	validateApiTokenFn  func(ctx context.Context, in *authv1.ValidateApiTokenRequest, opts ...grpc.CallOption) (*authv1.ValidateApiTokenResponse, error)
}

func (f *fakeAuthServiceClient) RequestOTP(ctx context.Context, in *authv1.RequestOTPRequest, opts ...grpc.CallOption) (*authv1.RequestOTPResponse, error) {
	if f.requestOTPFn != nil {
		return f.requestOTPFn(ctx, in, opts...)
	}
	return &authv1.RequestOTPResponse{ExpiresAt: "2026-08-30T23:00:00Z"}, nil
}

func (f *fakeAuthServiceClient) VerifyOTP(ctx context.Context, in *authv1.VerifyOTPRequest, opts ...grpc.CallOption) (*authv1.VerifyOTPResponse, error) {
	if f.verifyOTPFn != nil {
		return f.verifyOTPFn(ctx, in, opts...)
	}
	return &authv1.VerifyOTPResponse{
		Tokens: &authv1.TokenResponse{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			ExpiresAt:    "2026-08-30T23:00:00Z",
		},
	}, nil
}

func (f *fakeAuthServiceClient) LoginWithPassword(ctx context.Context, in *authv1.LoginWithPasswordRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error) {
	if f.loginWithPasswordFn != nil {
		return f.loginWithPasswordFn(ctx, in, opts...)
	}
	return &authv1.TokenResponse{
		AccessToken:  "mock-access-token",
		RefreshToken: "mock-refresh-token",
		ExpiresAt:    "2026-08-30T23:00:00Z",
	}, nil
}

func (f *fakeAuthServiceClient) RefreshToken(ctx context.Context, in *authv1.RefreshTokenRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error) {
	if f.refreshTokenFn != nil {
		return f.refreshTokenFn(ctx, in, opts...)
	}
	return &authv1.TokenResponse{
		AccessToken:  "mock-refreshed-access-token",
		RefreshToken: "mock-new-refresh-token",
		ExpiresAt:    "2026-08-30T23:00:00Z",
	}, nil
}

func (f *fakeAuthServiceClient) CreateApiToken(ctx context.Context, in *authv1.CreateApiTokenRequest, opts ...grpc.CallOption) (*authv1.CreateApiTokenResponse, error) {
	if f.createApiTokenFn != nil {
		return f.createApiTokenFn(ctx, in, opts...)
	}
	return &authv1.CreateApiTokenResponse{}, nil
}

func (f *fakeAuthServiceClient) ListApiTokens(ctx context.Context, in *authv1.ListApiTokensRequest, opts ...grpc.CallOption) (*authv1.ListApiTokensResponse, error) {
	if f.listApiTokensFn != nil {
		return f.listApiTokensFn(ctx, in, opts...)
	}
	return &authv1.ListApiTokensResponse{}, nil
}

func (f *fakeAuthServiceClient) RevokeApiToken(ctx context.Context, in *authv1.RevokeApiTokenRequest, opts ...grpc.CallOption) (*authv1.RevokeApiTokenResponse, error) {
	if f.revokeApiTokenFn != nil {
		return f.revokeApiTokenFn(ctx, in, opts...)
	}
	return &authv1.RevokeApiTokenResponse{}, nil
}

func (f *fakeAuthServiceClient) ValidateApiToken(ctx context.Context, in *authv1.ValidateApiTokenRequest, opts ...grpc.CallOption) (*authv1.ValidateApiTokenResponse, error) {
	if f.validateApiTokenFn != nil {
		return f.validateApiTokenFn(ctx, in, opts...)
	}
	return nil, errors.New("unimplemented")
}

func TestDualAuth_ApiTokenScopes(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret-dual-auth")

	tokens := map[string]*authv1.ValidateApiTokenResponse{
		"oat_read_only": {
			UserId: "user-read",
			Scopes: []string{"read"},
		},
		"oat_write_only": {
			UserId: "user-write",
			Scopes: []string{"write"},
		},
		"oat_read_write": {
			UserId: "user-read-write",
			Scopes: []string{"read", "write"},
		},
		"oat_empty_scope": {
			UserId: "user-legacy",
			Scopes: []string{},
		},
	}

	fakeClient := &fakeAuthServiceClient{
		validateApiTokenFn: func(ctx context.Context, in *authv1.ValidateApiTokenRequest, opts ...grpc.CallOption) (*authv1.ValidateApiTokenResponse, error) {
			if resp, ok := tokens[in.Secret]; ok {
				return resp, nil
			}
			return nil, errors.New("invalid token")
		},
	}

	tests := []struct {
		name           string
		method         string
		token          string
		expectedStatus int
		expectUserID   string
	}{
		{
			name:           "GET request with read scope -> 200 OK",
			method:         http.MethodGet,
			token:          "oat_read_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-read",
		},
		{
			name:           "POST request with read scope -> 403 Forbidden",
			method:         http.MethodPost,
			token:          "oat_read_only",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST request with write scope -> 200 OK",
			method:         http.MethodPost,
			token:          "oat_write_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-write",
		},
		{
			name:           "GET request with write scope -> 200 OK",
			method:         http.MethodGet,
			token:          "oat_write_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-write",
		},
		{
			name:           "HEAD request with read scope -> 200 OK",
			method:         http.MethodHead,
			token:          "oat_read_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-read",
		},
		{
			name:           "OPTIONS request with read scope -> 200 OK",
			method:         http.MethodOptions,
			token:          "oat_read_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-read",
		},
		{
			name:           "PUT request with read scope -> 403 Forbidden",
			method:         http.MethodPut,
			token:          "oat_read_only",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "DELETE request with read scope -> 403 Forbidden",
			method:         http.MethodDelete,
			token:          "oat_read_only",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "PATCH request with write scope -> 200 OK",
			method:         http.MethodPatch,
			token:          "oat_write_only",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-write",
		},
		{
			name:           "Legacy token (empty scopes) GET -> 200 OK",
			method:         http.MethodGet,
			token:          "oat_empty_scope",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-legacy",
		},
		{
			name:           "Legacy token (empty scopes) POST -> 200 OK",
			method:         http.MethodPost,
			token:          "oat_empty_scope",
			expectedStatus: http.StatusOK,
			expectUserID:   "user-legacy",
		},
		{
			name:           "Invalid API token -> 401 Unauthorized",
			method:         http.MethodGet,
			token:          "oat_nonexistent",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotUserID string
			var gotHeaderUser string

			innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUserID = UserIDFromContext(r.Context())
				gotHeaderUser = r.Header.Get("X-User-Id")
				w.WriteHeader(http.StatusOK)
			})

			handler := DualAuth(fakeClient, innerHandler)

			req := httptest.NewRequest(tc.method, "/api/v1/resource", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
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
					t.Errorf("expected context user ID %q, got %q", tc.expectUserID, gotUserID)
				}
				if gotHeaderUser != tc.expectUserID {
					t.Errorf("expected header X-User-Id %q, got %q", tc.expectUserID, gotHeaderUser)
				}
			} else {
				if called {
					t.Errorf("inner handler should not have been called on failure (status %d)", rec.Code)
				}
			}
		})
	}
}

func TestDualAuth_JWT(t *testing.T) {
	secret := []byte("test-dual-auth-jwt-secret")
	t.Setenv("JWT_SECRET", "test-dual-auth-jwt-secret")

	validToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "jwt-user-456",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("failed to create valid jwt: %v", err)
	}

	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "jwt-user-456",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	}).SignedString(secret)
	if err != nil {
		t.Fatalf("failed to create expired jwt: %v", err)
	}

	wrongKeyToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "jwt-user-456",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}).SignedString([]byte("wrong-key"))
	if err != nil {
		t.Fatalf("failed to create wrong key jwt: %v", err)
	}

	fakeClient := &fakeAuthServiceClient{}

	tests := []struct {
		name           string
		authHeader     string
		setAuthHeader  bool
		expectedStatus int
		expectUserID   string
	}{
		{
			name:           "valid jwt token",
			authHeader:     "Bearer " + validToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusOK,
			expectUserID:   "jwt-user-456",
		},
		{
			name:           "missing auth header",
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
			name:           "expired jwt token",
			authHeader:     "Bearer " + expiredToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "wrong key jwt token",
			authHeader:     "Bearer " + wrongKeyToken,
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed jwt token",
			authHeader:     "Bearer malformed.jwt",
			setAuthHeader:  true,
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			var gotUserID string
			var gotHeaderUser string

			innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUserID = UserIDFromContext(r.Context())
				gotHeaderUser = r.Header.Get("X-User-Id")
				w.WriteHeader(http.StatusOK)
			})

			handler := DualAuth(fakeClient, innerHandler)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/jwt-protected", nil)
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
					t.Errorf("expected context user ID %q, got %q", tc.expectUserID, gotUserID)
				}
				if gotHeaderUser != tc.expectUserID {
					t.Errorf("expected header X-User-Id %q, got %q", tc.expectUserID, gotHeaderUser)
				}
			} else {
				if called {
					t.Errorf("inner handler should not have been called on failure")
				}
			}
		})
	}
}

func TestDualAuth_MissingSecret(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	t.Setenv("DEPLOYMENT_ENVIRONMENT", "production")

	fakeClient := &fakeAuthServiceClient{}
	handler := DualAuth(fakeClient, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer something")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500 when JWT_SECRET missing in prod, got %d", rec.Code)
	}
}

func TestAuthHandlers_Endpoints(t *testing.T) {
	fakeClient := &fakeAuthServiceClient{
		requestOTPFn: func(ctx context.Context, in *authv1.RequestOTPRequest, opts ...grpc.CallOption) (*authv1.RequestOTPResponse, error) {
			if in.Email == "invalid@example.com" {
				return nil, errors.New("user not found")
			}
			return &authv1.RequestOTPResponse{ExpiresAt: "2026-08-30T23:59:59Z"}, nil
		},
		verifyOTPFn: func(ctx context.Context, in *authv1.VerifyOTPRequest, opts ...grpc.CallOption) (*authv1.VerifyOTPResponse, error) {
			if in.Code != "123456" {
				return nil, errors.New("invalid code")
			}
			return &authv1.VerifyOTPResponse{
				Tokens: &authv1.TokenResponse{
					AccessToken:  "valid-access-token",
					RefreshToken: "valid-refresh-token",
					ExpiresAt:    "2026-08-30T23:59:59Z",
				},
			}, nil
		},
		loginWithPasswordFn: func(ctx context.Context, in *authv1.LoginWithPasswordRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error) {
			if in.Password != "correct-pass" {
				return nil, errors.New("bad credentials")
			}
			return &authv1.TokenResponse{
				AccessToken:  "login-access-token",
				RefreshToken: "login-refresh-token",
				ExpiresAt:    "2026-08-30T23:59:59Z",
			}, nil
		},
		refreshTokenFn: func(ctx context.Context, in *authv1.RefreshTokenRequest, opts ...grpc.CallOption) (*authv1.TokenResponse, error) {
			if in.RefreshToken != "valid-refresh" {
				return nil, errors.New("invalid refresh token")
			}
			return &authv1.TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				ExpiresAt:    "2026-08-30T23:59:59Z",
			}, nil
		},
	}

	handlers := NewAuthHandlers(fakeClient, nil)

	// 1. RequestOTP success & failure
	t.Run("RequestOTP_Success", func(t *testing.T) {
		body, _ := json.Marshal(otpRequestBody{Email: "test@example.com", Channel: "email"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/request", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.RequestOTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("RequestOTP_GRPCError", func(t *testing.T) {
		body, _ := json.Marshal(otpRequestBody{Email: "invalid@example.com", Channel: "email"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/request", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.RequestOTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("expected error status, got %d", rec.Code)
		}
	})

	t.Run("RequestOTP_BadJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/request", bytes.NewReader([]byte("not json")))
		rec := httptest.NewRecorder()
		handlers.RequestOTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	// 2. VerifyOTP success & failure
	t.Run("VerifyOTP_Success", func(t *testing.T) {
		body, _ := json.Marshal(otpVerifyBody{Email: "test@example.com", Code: "123456"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.VerifyOTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("VerifyOTP_GRPCError", func(t *testing.T) {
		body, _ := json.Marshal(otpVerifyBody{Email: "test@example.com", Code: "wrong-code"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/otp/verify", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.VerifyOTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("expected error status, got %d", rec.Code)
		}
	})

	// 3. Login success & failure
	t.Run("Login_Success", func(t *testing.T) {
		body, _ := json.Marshal(loginBody{Email: "user@example.com", Password: "correct-pass"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.Login(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("Login_GRPCError", func(t *testing.T) {
		body, _ := json.Marshal(loginBody{Email: "user@example.com", Password: "wrong-password"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.Login(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("expected error status, got %d", rec.Code)
		}
	})

	// 4. RefreshToken success & failure
	t.Run("RefreshToken_Success", func(t *testing.T) {
		body, _ := json.Marshal(refreshBody{RefreshToken: "valid-refresh"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.RefreshToken(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("RefreshToken_GRPCError", func(t *testing.T) {
		body, _ := json.Marshal(refreshBody{RefreshToken: "bad-refresh"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handlers.RefreshToken(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("expected error status, got %d", rec.Code)
		}
	})
}
