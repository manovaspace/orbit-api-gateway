package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	orbittoken "github.com/manovaspace/orbit-auth/token"
)

type AuthHandlers struct {
	auth authv1.AuthServiceClient
	rl   *RateLimitConfig
}

func NewAuthHandlers(api authv1.AuthServiceClient, rl *RateLimitConfig) *AuthHandlers {
	return &AuthHandlers{auth: api, rl: rl}
}

type otpRequestBody struct {
	Identifier    string `json:"identifier"`
	Channel       string `json:"channel"`
	Email         string `json:"email"`
	CorrelationID string `json:"correlation_id"`
}

type otpVerifyBody struct {
	Identifier string `json:"identifier"`
	Channel    string `json:"channel"`
	Email      string `json:"email"`
	Code       string `json:"code"`
}

type refreshBody struct {
	RefreshToken string `json:"refresh_token"`
}

type loginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandlers) RequestOTP(w http.ResponseWriter, r *http.Request) {
	var body otpRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	id := body.Identifier
	if id == "" {
		id = body.Email
	}
	if h.rl != nil && !h.rl.allowIdentifier(w, r, id) {
		return
	}
	resp, err := h.auth.RequestOTP(r.Context(), &authv1.RequestOTPRequest{
		Identifier:    body.Identifier,
		Channel:       body.Channel,
		Email:         body.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		CorrelationId: body.CorrelationID,
	})
	if err != nil {
		writeGRPCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"expires_at": resp.GetExpiresAt()})
}

func (h *AuthHandlers) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	var body otpVerifyBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	resp, err := h.auth.VerifyOTP(r.Context(), &authv1.VerifyOTPRequest{
		Identifier: body.Identifier,
		Channel:    body.Channel,
		Email:      body.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		Code:       body.Code,
	})
	if err != nil {
		writeGRPCError(w, err)
		return
	}
	tokens := resp.GetTokens()
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  tokens.GetAccessToken(),
		"refresh_token": tokens.GetRefreshToken(),
		"expires_at":    tokens.GetExpiresAt(),
	})
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var body loginBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	resp, err := h.auth.LoginWithPassword(r.Context(), &authv1.LoginWithPasswordRequest{
		Email:    body.Email,
		Password: body.Password,
	})
	if err != nil {
		writeGRPCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  resp.GetAccessToken(),
		"refresh_token": resp.GetRefreshToken(),
		"expires_at":    resp.GetExpiresAt(),
	})
}

func (h *AuthHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var body refreshBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	resp, err := h.auth.RefreshToken(r.Context(), &authv1.RefreshTokenRequest{
		RefreshToken: body.RefreshToken,
	})
	if err != nil {
		writeGRPCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  resp.GetAccessToken(),
		"refresh_token": resp.GetRefreshToken(),
		"expires_at":    resp.GetExpiresAt(),
	})
}

func jwtKeySet() (orbittoken.KeySet, error) {
	directory := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEYS_DIR"))
	if directory == "" {
		return nil, fmt.Errorf("JWT_PUBLIC_KEYS_DIR is required")
	}
	return orbittoken.LoadKeySet(directory)
}

// ValidateJWTVerificationKey checks the configured key at process startup.
func ValidateJWTVerificationKey() error {
	_, err := jwtKeySet()
	return err
}

// JWKSHandler publishes the configured public verification key set.
func JWKSHandler() http.Handler {
	keys, keyErr := jwtKeySet()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if keyErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(keys.Document())
	})
}

type scopeKey struct{}

func DualAuth(auth authv1.AuthServiceClient, next http.Handler) http.Handler {
	keys, keyErr := jwtKeySet()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keyErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tokenStr := strings.TrimPrefix(authz, "Bearer ")
		if strings.HasPrefix(tokenStr, "oat_") {
			resp, err := auth.ValidateApiToken(r.Context(), &authv1.ValidateApiTokenRequest{Secret: tokenStr})
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
			scopes := resp.GetScopes()
			if !scopesAllow(r, scopes) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient scope"})
				return
			}
			r.Header.Set("X-User-Id", resp.GetUserId())
			ctx := context.WithValue(r.Context(), userIDKey{}, resp.GetUserId())
			ctx = context.WithValue(ctx, scopeKey{}, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		claims, err := orbittoken.ParseAccessToken(tokenStr, keys)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		sub := claims.Subject
		r.Header.Set("X-User-Id", sub)
		ctx := context.WithValue(r.Context(), userIDKey{}, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scopesAllow: empty scopes = full access (legacy tokens). Non-empty: GET/HEAD/OPTIONS need read|write; others need write.
func scopesAllow(r *http.Request, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	needWrite := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
	for _, s := range scopes {
		s = strings.ToLower(strings.TrimSpace(s))
		if needWrite && s == "write" {
			return true
		}
		if !needWrite && (s == "read" || s == "write") {
			return true
		}
	}
	return false
}

// JWTAuth validates RS256 JWTs only (tests / simple routes).
func JWTAuth(next http.Handler) http.Handler {
	keys, keyErr := jwtKeySet()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if keyErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tokenStr := strings.TrimPrefix(authz, "Bearer ")
		claims, err := orbittoken.ParseAccessToken(tokenStr, keys)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		sub := claims.Subject
		ctx := context.WithValue(r.Context(), userIDKey{}, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type userIDKey struct{}

func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(userIDKey{}).(string)
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
