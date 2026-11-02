package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
)

// TokenAuth validates bearer credentials for the routes a deployment binary
// mounts. The platform binary itself mounts none of them.
type TokenAuth struct {
	svc    *application.Service
	secret string
}

// NewTokenAuth builds the middleware. An empty secret makes every request fail
// closed with 500, as before.
func NewTokenAuth(svc *application.Service, secret string) *TokenAuth {
	return &TokenAuth{svc: svc, secret: secret}
}

type scopeKey struct{}

type userIDKey struct{}

// Dual accepts an oat_ API token (validated upstream, scope-checked here) or an
// HS256 JWT signed with the configured secret.
func (a *TokenAuth) Dual(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tokenString := strings.TrimPrefix(authorization, "Bearer ")
		if strings.HasPrefix(tokenString, "oat_") {
			identity, err := a.svc.ValidateAPIToken(r.Context(), tokenString)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}
			if !scopesAllow(r, identity.Scopes) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient scope"})
				return
			}
			r.Header.Set("X-User-Id", identity.UserID)
			ctx := context.WithValue(r.Context(), userIDKey{}, identity.UserID)
			ctx = context.WithValue(ctx, scopeKey{}, identity.Scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		subject, ok := a.jwtSubject(w, tokenString)
		if !ok {
			return
		}
		r.Header.Set("X-User-Id", subject)
		ctx := context.WithValue(r.Context(), userIDKey{}, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWT accepts only an HS256 JWT signed with the configured secret. It attaches
// the subject to the request context and, unlike Dual, sets no header: that is
// the contract of the handler it replaces.
func (a *TokenAuth) JWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		subject, ok := a.jwtSubject(w, strings.TrimPrefix(authorization, "Bearer "))
		if !ok {
			return
		}
		ctx := context.WithValue(r.Context(), userIDKey{}, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jwtSubject parses an HS256 JWT and writes the 401 response when it does not
// verify.
func (a *TokenAuth) jwtSubject(w http.ResponseWriter, tokenString string) (string, bool) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected alg")
		}
		return []byte(a.secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return "", false
	}
	subject, _ := claims["sub"].(string)
	return subject, true
}

// scopesAllow: empty scopes = full access (legacy tokens). Non-empty: GET, HEAD
// and OPTIONS need read or write; every other method needs write.
func scopesAllow(r *http.Request, scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	needWrite := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if needWrite && scope == "write" {
			return true
		}
		if !needWrite && (scope == "read" || scope == "write") {
			return true
		}
	}
	return false
}

// UserIDFromContext returns the identity the token middleware attached.
func UserIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(userIDKey{}).(string)
	return value
}
