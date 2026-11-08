package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/staffoidc"
)

// TokenAuth validates bearer credentials for the routes a deployment binary
// mounts. The platform binary itself mounts none of them.
type TokenAuth struct {
	svc         *application.Service
	secret      string
	staffSecret string
	// oidc verifies Keycloak staff access tokens (RS256). Nil leaves staff
	// sign-in to the HS256 path only.
	oidc *staffoidc.Verifier
	// hs256StaffDisabled refuses HS256 staff tokens. The zero value keeps them
	// accepted, which is the default.
	hs256StaffDisabled bool
}

const (
	// staffReasonHeader carries the audited reason for a Keycloak staff request.
	// It is required for every non-read request.
	staffReasonHeader = "X-Staff-Reason"
	// staffTargetOrgHeader names the tenant a Keycloak staff request acts on.
	staffTargetOrgHeader = "X-Staff-Target-Org"
	// keycloakSubjectPrefix keeps Keycloak staff subjects apart from orbit-auth
	// user ids.
	keycloakSubjectPrefix = "keycloak:"
)

// NewTokenAuth builds the middleware. An empty secret makes every request fail
// closed with 500, as before.
func NewTokenAuth(svc *application.Service, secret string) *TokenAuth {
	return &TokenAuth{svc: svc, secret: secret, staffSecret: secret}
}

// WithStaffSecret sets a distinct signing secret for staff credentials.
func (a *TokenAuth) WithStaffSecret(staffSecret string) *TokenAuth {
	if staffSecret != "" {
		a.staffSecret = staffSecret
	}
	return a
}

// WithStaffOIDC enables Keycloak staff tokens. A nil verifier leaves them off.
func (a *TokenAuth) WithStaffOIDC(verifier *staffoidc.Verifier) *TokenAuth {
	a.oidc = verifier
	return a
}

// WithStaffHS256Disabled refuses HS256 staff tokens when disabled is true.
func (a *TokenAuth) WithStaffHS256Disabled(disabled bool) *TokenAuth {
	a.hs256StaffDisabled = disabled
	return a
}

type scopeKey struct{}

type userIDKey struct{}

type staffSubjectKey struct{}

type isStaffKey struct{}

type breakGlassReasonKey struct{}

type breakGlassKey struct{}

type staffIdentityKey struct{}

type targetOrgKey struct{}

// keycloakStaffKey marks a context whose staff identity was verified by Keycloak.
type keycloakStaffKey struct{}

// StaffIdentity holds claims from a staff token.
type StaffIdentity struct {
	StaffSubject     string `json:"staff_subject"`
	IsStaff          bool   `json:"is_staff"`
	BreakGlass       bool   `json:"break_glass"`
	BreakGlassReason string `json:"break_glass_reason"`
	TargetOrgID      string `json:"target_org_id,omitempty"`
}

// Dual accepts an oat_ API token (validated upstream, scope-checked here) or an
// HS256 JWT signed with the configured secret.
func (a *TokenAuth) Dual(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret == "" && a.staffSecret == "" {
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
			ctx = context.WithValue(ctx, isStaffKey{}, false)
			ctx = context.WithValue(ctx, scopeKey{}, identity.Scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		subject, claims, ok := a.jwtSubject(w, tokenString)
		if !ok {
			return
		}
		r.Header.Set("X-User-Id", subject)
		ctx := enrichContext(r.Context(), claims, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// JWT accepts only an HS256 JWT signed with the configured secret. It attaches
// the subject to the request context and, unlike Dual, sets no header: that is
// the contract of the handler it replaces.
func (a *TokenAuth) JWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret == "" && a.staffSecret == "" {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		subject, claims, ok := a.jwtSubject(w, strings.TrimPrefix(authorization, "Bearer "))
		if !ok {
			return
		}
		ctx := enrichContext(r.Context(), claims, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireStaff ensures that the request carries an authenticated staff identity.
// If the caller is authenticated as a tenant user or admin, it returns 403 Forbidden.
// If the caller is unauthenticated or has an invalid token, it returns 401 Unauthorized.
func (a *TokenAuth) RequireStaff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.secret == "" && a.staffSecret == "" && a.oidc == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "auth misconfigured"})
			return
		}
		// If context already contains authenticated identity:
		if IsStaffFromContext(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		if UserIDFromContext(r.Context()) != "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "staff access required"})
			return
		}

		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Bearer ") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}
		tokenString := strings.TrimPrefix(authorization, "Bearer ")
		alg, kid, ok := unverifiedHeader(tokenString)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		if alg == "RS256" && a.oidc != nil && kid != "" {
			a.requireKeycloakStaff(next, w, r, tokenString)
			return
		}
		if a.hs256StaffDisabled {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		claims, ok := a.parseToken(tokenString)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}
		staff, isStaff := extractStaffIdentity(claims)
		if !isStaff {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "staff access required"})
			return
		}
		subject, _ := claims["sub"].(string)
		if subject == "" {
			subject = staff.StaffSubject
		}
		ctx := enrichContext(r.Context(), claims, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireKeycloakStaff verifies a Keycloak staff token and attaches the staff
// identity. The break-glass reason and the target org come from request
// headers, never from token claims.
func (a *TokenAuth) requireKeycloakStaff(next http.Handler, w http.ResponseWriter, r *http.Request, tokenString string) {
	identity, err := a.oidc.Verify(r.Context(), tokenString)
	if err != nil {
		if errors.Is(err, staffoidc.ErrNotAllowed) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "staff access required"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}
	reason := strings.TrimSpace(r.Header.Get(staffReasonHeader))
	if reason == "" && !isReadMethod(r.Method) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "staff reason required"})
		return
	}
	targetOrg := strings.TrimSpace(r.Header.Get(staffTargetOrgHeader))
	staff := StaffIdentity{
		StaffSubject:     keycloakSubjectPrefix + identity.Subject,
		IsStaff:          true,
		BreakGlass:       targetOrg != "",
		BreakGlassReason: reason,
		TargetOrgID:      targetOrg,
	}
	next.ServeHTTP(w, r.WithContext(enrichStaffContext(r.Context(), staff)))
}

// StaffRateLimit applies the class budget to a Keycloak-authenticated staff
// caller, keyed on the staff subject. It runs after RequireStaff. Other callers
// and deployments without a limiter pass through unchanged.
func (a *TokenAuth) StaffRateLimit(class string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := keycloakStaffSubject(r.Context())
		if !ok || a.svc == nil || !a.svc.HasLimiter() {
			next.ServeHTTP(w, r)
			return
		}
		decision, err := a.svc.CheckStaffLimit(r.Context(), class, subject)
		if err != nil {
			writeLimitError(w, err)
			return
		}
		setRateLimitHeaders(w, decision)
		next.ServeHTTP(w, r)
	})
}

// AuditHook wraps next and writes staff break-glass and admin actions to the audit log.
func (a *TokenAuth) AuditHook(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		if a.svc == nil || !a.svc.HasAudit() {
			return
		}

		ctx := r.Context()
		isStaff := IsStaffFromContext(ctx)
		staffSubject := StaffSubjectFromContext(ctx)
		breakGlass := BreakGlassFromContext(ctx)
		reason := BreakGlassReasonFromContext(ctx)
		userID := UserIDFromContext(ctx)

		actor := userID
		actorType := "user"
		if isStaff {
			actor = staffSubject
			if actor == "" {
				actor = userID
			}
			actorType = "staff"
		}

		if actor == "" {
			return
		}

		orgID := TargetOrgFromContext(ctx)
		if orgID == "" {
			orgID = r.PathValue("org_id")
		}
		if orgID == "" {
			orgID = r.Header.Get("X-Org-Id")
		}

		entry := domain.AuditEntry{
			OrgID:      orgID,
			Actor:      actor,
			ActorType:  actorType,
			IsStaff:    isStaff,
			BreakGlass: breakGlass,
			Reason:     reason,
			Action:     r.Method + " " + r.URL.Path,
			Resource:   r.URL.Path,
		}
		_ = a.svc.RecordAudit(ctx, entry)
	})
}

// HandleStaffBreakGlass handles explicit break-glass requests and records them in the audit log.
func (a *TokenAuth) HandleStaffBreakGlass(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !IsStaffFromContext(ctx) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "staff access required"})
		return
	}
	reason := BreakGlassReasonFromContext(ctx)
	if reason == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "break-glass reason required"})
		return
	}
	staffSubject := StaffSubjectFromContext(ctx)
	orgID := TargetOrgFromContext(ctx)
	if orgID == "" {
		orgID = r.PathValue("org_id")
	}
	if orgID == "" {
		orgID = r.Header.Get("X-Org-Id")
	}

	if a.svc != nil && a.svc.HasAudit() {
		_ = a.svc.RecordAudit(ctx, domain.AuditEntry{
			OrgID:      orgID,
			Actor:      staffSubject,
			ActorType:  "staff",
			IsStaff:    true,
			BreakGlass: true,
			Reason:     reason,
			Action:     "break_glass.access",
			Resource:   r.URL.Path,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "break_glass_granted",
		"staff_subject": staffSubject,
		"org_id":        orgID,
		"reason":        reason,
	})
}

// StaffAuth validates staff credentials and ensures staff-only access.
type StaffAuth struct {
	tokenAuth *TokenAuth
}

// NewStaffAuth wraps TokenAuth to provide staff authorization.
func NewStaffAuth(tokenAuth *TokenAuth) *StaffAuth {
	return &StaffAuth{tokenAuth: tokenAuth}
}

// Wrap returns an http.Handler that enforces staff-only access.
func (s *StaffAuth) Wrap(next http.Handler) http.Handler {
	return s.tokenAuth.RequireStaff(next)
}

// parseToken parses an HS256 JWT using secret or staffSecret.
func (a *TokenAuth) parseToken(tokenString string) (jwt.MapClaims, bool) {
	secrets := []string{a.secret}
	if a.staffSecret != "" && a.staffSecret != a.secret {
		secrets = append(secrets, a.staffSecret)
	}

	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		c := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, c, func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf("unexpected alg")
			}
			return []byte(sec), nil
		}, jwt.WithValidMethods([]string{"HS256"}))
		if err == nil && token.Valid {
			return c, true
		}
	}
	return nil, false
}

func extractStaffIdentity(claims jwt.MapClaims) (StaffIdentity, bool) {
	var staff StaffIdentity
	if ss, ok := claims["staff_subject"].(string); ok && ss != "" {
		staff.StaffSubject = ss
		staff.IsStaff = true
	}
	if isStaff, ok := claims["is_staff"].(bool); ok && isStaff {
		staff.IsStaff = true
	}
	if bg, ok := claims["break_glass"].(bool); ok {
		staff.BreakGlass = bg
	}
	if r, ok := claims["reason"].(string); ok {
		staff.BreakGlassReason = r
	}
	if org, ok := claims["org"].(string); ok && org != "" {
		staff.TargetOrgID = org
	} else if orgID, ok := claims["org_id"].(string); ok && orgID != "" {
		staff.TargetOrgID = orgID
	} else if to, ok := claims["target_org"].(string); ok && to != "" {
		staff.TargetOrgID = to
	}

	if staff.IsStaff && staff.StaffSubject == "" {
		if sub, ok := claims["sub"].(string); ok {
			staff.StaffSubject = sub
		}
	}
	return staff, staff.IsStaff
}

func enrichContext(ctx context.Context, claims jwt.MapClaims, subject string) context.Context {
	ctx = context.WithValue(ctx, userIDKey{}, subject)
	staff, isStaff := extractStaffIdentity(claims)
	ctx = context.WithValue(ctx, isStaffKey{}, isStaff)
	if isStaff {
		if staff.StaffSubject != "" {
			ctx = context.WithValue(ctx, staffSubjectKey{}, staff.StaffSubject)
		} else {
			ctx = context.WithValue(ctx, staffSubjectKey{}, subject)
		}
		ctx = context.WithValue(ctx, breakGlassKey{}, staff.BreakGlass)
		ctx = context.WithValue(ctx, breakGlassReasonKey{}, staff.BreakGlassReason)
		ctx = context.WithValue(ctx, staffIdentityKey{}, staff)
		if staff.TargetOrgID != "" {
			ctx = context.WithValue(ctx, targetOrgKey{}, staff.TargetOrgID)
		}
	}
	return ctx
}

// jwtSubject parses an HS256 JWT and writes the 401 response when it does not verify.
// With HS256 staff tokens disabled, a token that carries staff claims is refused here
// too, so it cannot reach staff context through a tenant route.
func (a *TokenAuth) jwtSubject(w http.ResponseWriter, tokenString string) (string, jwt.MapClaims, bool) {
	claims, ok := a.parseToken(tokenString)
	if ok && a.hs256StaffDisabled {
		if _, isStaff := extractStaffIdentity(claims); isStaff {
			ok = false
		}
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return "", nil, false
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		if ss, ok := claims["staff_subject"].(string); ok {
			subject = ss
		}
	}
	return subject, claims, true
}

// unverifiedHeader reads alg and kid from the token header without checking the
// signature. The result only chooses which verifier runs.
func unverifiedHeader(tokenString string) (alg, kid string, ok bool) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", "", false
	}
	alg, _ = token.Header["alg"].(string)
	kid, _ = token.Header["kid"].(string)
	return alg, kid, true
}

// isReadMethod reports whether a request only reads. Reads need no break-glass reason.
func isReadMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// enrichStaffContext attaches a verified staff identity. Keycloak subjects are
// already prefixed, so they never equal an orbit-auth user id.
func enrichStaffContext(ctx context.Context, staff StaffIdentity) context.Context {
	ctx = context.WithValue(ctx, userIDKey{}, staff.StaffSubject)
	ctx = context.WithValue(ctx, isStaffKey{}, true)
	ctx = context.WithValue(ctx, staffSubjectKey{}, staff.StaffSubject)
	ctx = context.WithValue(ctx, breakGlassKey{}, staff.BreakGlass)
	ctx = context.WithValue(ctx, breakGlassReasonKey{}, staff.BreakGlassReason)
	ctx = context.WithValue(ctx, staffIdentityKey{}, staff)
	ctx = context.WithValue(ctx, keycloakStaffKey{}, true)
	if staff.TargetOrgID != "" {
		ctx = context.WithValue(ctx, targetOrgKey{}, staff.TargetOrgID)
	}
	return ctx
}

// keycloakStaffSubject returns the staff subject when the caller was verified by Keycloak.
func keycloakStaffSubject(ctx context.Context) (string, bool) {
	verified, _ := ctx.Value(keycloakStaffKey{}).(bool)
	if !verified {
		return "", false
	}
	return StaffSubjectFromContext(ctx), true
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

// StaffSubjectFromContext returns the staff subject identity from context.
func StaffSubjectFromContext(ctx context.Context) string {
	v, _ := ctx.Value(staffSubjectKey{}).(string)
	return v
}

// IsStaffFromContext reports whether the context caller has a staff identity.
func IsStaffFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(isStaffKey{}).(bool)
	return v
}

// BreakGlassReasonFromContext returns the audited break-glass reason from context.
func BreakGlassReasonFromContext(ctx context.Context) string {
	v, _ := ctx.Value(breakGlassReasonKey{}).(string)
	return v
}

// BreakGlassFromContext reports whether the request has break-glass access enabled.
func BreakGlassFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(breakGlassKey{}).(bool)
	return v
}

// TargetOrgFromContext returns the target org ID for break-glass or cross-tenant operations.
func TargetOrgFromContext(ctx context.Context) string {
	v, _ := ctx.Value(targetOrgKey{}).(string)
	return v
}

// StaffIdentityFromContext returns the complete StaffIdentity, if present.
func StaffIdentityFromContext(ctx context.Context) (StaffIdentity, bool) {
	v, ok := ctx.Value(staffIdentityKey{}).(StaffIdentity)
	return v, ok
}
