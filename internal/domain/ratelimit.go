package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Rate-limit classes, one per limited route.
const (
	ClassAuthOTPRequest      = "auth_otp_request"
	ClassAuthOTPVerify       = "auth_otp_verify"
	ClassAuthPassword        = "auth_password"
	ClassAuthRefresh         = "auth_refresh"
	ClassOwnershipChallenge  = "system_ownership_challenge"
	ClassOwnershipVerify     = "system_ownership_verify"
	ClassDevOnboardClaim     = "dev_onboard_claim"
	ClassAdminChallenge      = "admin_challenge"
	ClassAdminVerify         = "admin_verify"
	ClassOnboardClaim        = "onboard_claim"
	identifierKeyPrefix      = "rl:" + ClassAuthOTPRequest + ":id:"
	clientKeyPrefix          = "rl:"
	authClassOTPRequestLimit = 5
	authClassOTPVerifyLimit  = 20
	authClassPasswordLimit   = 10
	authClassRefreshLimit    = 30
	otpIdentifierWindowLimit = 3
	defaultAuthPolicyWindow  = time.Minute
	// SignupIPLimit is the strict per-IP budget for signup and signup
	// verification. InviteAcceptIPLimit is the same budget for accepting an
	// invitation.
	SignupIPLimit       = 5
	InviteAcceptIPLimit = 5
	// TenantResolveIPLimit is the per-IP budget for the public tenant lookup the
	// edge makes before anyone signs in. It is generous because the caller is
	// usually the web edge, whose egress addresses are few and shared by every
	// tenant; the edge caches answers for 30 seconds, so the real rate is far
	// below it. It exists to stop scraping, not to meter the edge.
	TenantResolveIPLimit = 600
	// OrgRouteLimit is the per-organization budget for organization-scoped
	// routes.
	OrgRouteLimit = 60
	// OrgRouteIPLimit is the per-IP budget on organization routes, counted
	// before authentication, so one client cannot flood orbit-auth with junk
	// tokens.
	OrgRouteIPLimit = 300
	RouteWindow     = time.Minute
)

// Policy describes one token-bucket class.
type Policy struct {
	Class  string
	Limit  int
	Window time.Duration
}

// Decision is the outcome of one rate-limit check.
type Decision struct {
	Allowed    bool
	Limit      int
	Remaining  int
	ResetAt    time.Time
	RetryAfter time.Duration
}

// Limiter is the rate-limit port. Every check reaches the outside world
// through it; the memory and Redis strategies are adapters.
type Limiter interface {
	Allow(ctx context.Context, key string, policy Policy) (Decision, error)
}

// LimitError reports a rejected or unavailable rate-limit check. The caller
// needs the decision to render the remaining-budget headers.
type LimitError struct {
	Decision    Decision
	Unavailable bool
}

// Error implements error.
func (e *LimitError) Error() string {
	if e.Unavailable {
		return "rate limiter unavailable"
	}
	return "rate limit exceeded"
}

// DefaultAuthPolicies returns the auth class limits (ADR-018 v1 defaults).
func DefaultAuthPolicies() map[string]Policy {
	return map[string]Policy{
		ClassAuthOTPRequest: {Class: ClassAuthOTPRequest, Limit: authClassOTPRequestLimit, Window: defaultAuthPolicyWindow},
		ClassAuthOTPVerify:  {Class: ClassAuthOTPVerify, Limit: authClassOTPVerifyLimit, Window: defaultAuthPolicyWindow},
		ClassAuthPassword:   {Class: ClassAuthPassword, Limit: authClassPasswordLimit, Window: defaultAuthPolicyWindow},
		ClassAuthRefresh:    {Class: ClassAuthRefresh, Limit: authClassRefreshLimit, Window: defaultAuthPolicyWindow},
	}
}

// OTPRequestIdentifierPolicy is the per-identifier OTP request limit.
func OTPRequestIdentifierPolicy() Policy {
	return Policy{Class: ClassAuthOTPRequest, Limit: otpIdentifierWindowLimit, Window: defaultAuthPolicyWindow}
}

// IPRoutePolicy is the per-IP budget for a public route. The route template is
// the class and the rate-limit key's route name.
func IPRoutePolicy(route string, limit int) Policy {
	return Policy{Class: route, Limit: limit, Window: RouteWindow}
}

// OrgRoutePolicy is the per-organization budget for an organization route. The
// route template is the class and the rate-limit key's route name.
func OrgRoutePolicy(route string) Policy {
	return Policy{Class: route, Limit: OrgRouteLimit, Window: RouteWindow}
}

// PolicyFor returns the class policy. A class without a policy gets the zero
// policy, exactly as the edge behaved before: the limiter still answers and the
// response still carries its headers.
func PolicyFor(class string) Policy {
	return DefaultAuthPolicies()[class]
}

// ClientKey is the per-class, per-client bucket key.
func ClientKey(class, clientIP string) string {
	return clientKeyPrefix + class + ":" + clientIP
}

// IdentifierKey is the per-identifier OTP request bucket key.
func IdentifierKey(identifier string) string {
	return identifierKeyPrefix + HashIdentifier(identifier)
}

// HashIdentifier hashes an identifier so the raw address never becomes a
// rate-limit key or a log value.
func HashIdentifier(identifier string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(identifier))))
	return hex.EncodeToString(sum[:])[:16]
}
