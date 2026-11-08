// Package domain holds the edge's types and the ports every other layer
// depends on. It imports no infrastructure package, database driver, HTTP
// framework or process package.
package domain

import (
	"context"
	"errors"
	"time"
)

// Kind classifies a failure so the HTTP edge chooses a status code without
// knowing which layer produced the error.
type Kind int

// Failure kinds mirror the codes the upstream orbit-auth gRPC API returns.
const (
	KindInternal Kind = iota
	KindInvalidArgument
	KindUnauthenticated
	KindPermissionDenied
	KindFailedPrecondition
	KindResourceExhausted
	// KindNotFound is a missing resource, including an organization the caller
	// is not an active member of.
	KindNotFound
	// KindConflict is a state conflict, such as removing the last owner.
	KindConflict
	// KindBadGateway is an upstream failure with no client-safe detail.
	KindBadGateway
)

// Error is a client-facing failure. Message is the exact text the edge returns.
type Error struct {
	Kind    Kind
	Message string
}

// Error implements error.
func (e *Error) Error() string { return e.Message }

// NewError builds a client-facing failure.
func NewError(kind Kind, message string) *Error {
	return &Error{Kind: kind, Message: message}
}

// AsError reports the *Error wrapped in err, if any.
func AsError(err error) (*Error, bool) {
	var target *Error
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// Clock supplies the current time. The challenge TTL and the ownership
// fingerprint read it, so tests can pin both.
type Clock interface {
	Now() time.Time
}

// CodeGenerator supplies the six-digit ownership challenge code.
type CodeGenerator interface {
	NewCode() string
}

// Assets is the set of static documents the edge publishes byte for byte.
type Assets interface {
	InstallScript() []byte
	OpenAPISpec() ([]byte, error)
	Manifest() ([]byte, error)
}

// TokenPair is an access/refresh pair returned by orbit-auth.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    string
}

// OTPRequest is one one-time-password request.
type OTPRequest struct {
	Identifier    string
	Channel       string
	Email         string
	CorrelationID string
}

// OTPVerification checks one one-time password.
type OTPVerification struct {
	Identifier string
	Channel    string
	Email      string
	Code       string
}

// PasswordLogin is a password login by email address or E.164 mobile number.
type PasswordLogin struct {
	Identifier string
	Email      string
	Password   string
}

// APIIdentity is the identity behind a validated API token.
type APIIdentity struct {
	UserID string
	Scopes []string
}

// AuthService is the upstream orbit-auth port.
type AuthService interface {
	RequestOTP(ctx context.Context, in OTPRequest) (expiresAt string, err error)
	VerifyOTP(ctx context.Context, in OTPVerification) (TokenPair, error)
	LoginWithPassword(ctx context.Context, in PasswordLogin) (TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string) (TokenPair, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
	ValidateAPIToken(ctx context.Context, secret string) (APIIdentity, error)
}
