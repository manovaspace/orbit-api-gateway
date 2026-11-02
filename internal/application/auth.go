package application

import (
	"context"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// OTPReceipt is the answer to an OTP request. IdentifierLimit carries the
// per-identifier budget the request consumed, so the edge can render its
// headers on the success response.
type OTPReceipt struct {
	ExpiresAt       string
	IdentifierLimit *domain.Decision
}

// RequestOTP asks orbit-auth for a one-time password. The identifier limit runs
// before the upstream call, exactly as the edge did before the refactor.
func (s *Service) RequestOTP(ctx context.Context, in domain.OTPRequest) (OTPReceipt, error) {
	identifier := in.Identifier
	if identifier == "" {
		identifier = in.Email
	}
	limit, err := s.checkIdentifierLimit(ctx, identifier)
	if err != nil {
		return OTPReceipt{}, err
	}
	expiresAt, err := s.auth.RequestOTP(ctx, in)
	if err != nil {
		return OTPReceipt{}, err
	}
	return OTPReceipt{ExpiresAt: expiresAt, IdentifierLimit: limit}, nil
}

// VerifyOTP exchanges a one-time password for a token pair.
func (s *Service) VerifyOTP(ctx context.Context, in domain.OTPVerification) (domain.TokenPair, error) {
	return s.auth.VerifyOTP(ctx, in)
}

// Login exchanges a password for a token pair. The identifier is the E.164
// mobile number or email address; the deprecated email field is the fallback.
func (s *Service) Login(ctx context.Context, in domain.PasswordLogin) (domain.TokenPair, error) {
	identifier := in.Identifier
	if identifier == "" {
		identifier = in.Email
	}
	return s.auth.LoginWithPassword(ctx, domain.PasswordLogin{
		Identifier: identifier,
		Password:   in.Password,
	})
}

// RefreshToken rotates a refresh token.
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (domain.TokenPair, error) {
	return s.auth.RefreshToken(ctx, refreshToken)
}

// ValidateAPIToken validates an oat_ API token and returns its identity.
func (s *Service) ValidateAPIToken(ctx context.Context, secret string) (domain.APIIdentity, error) {
	return s.auth.ValidateAPIToken(ctx, secret)
}

// checkIdentifierLimit applies the per-identifier OTP policy. An empty
// identifier is not addressable and consumes no budget, and no adapter is
// consulted, so no headers are written for it.
func (s *Service) checkIdentifierLimit(ctx context.Context, identifier string) (*domain.Decision, error) {
	if s.limiter == nil || strings.TrimSpace(identifier) == "" {
		return nil, nil
	}
	decision, err := s.allow(ctx, domain.IdentifierKey(identifier), domain.OTPRequestIdentifierPolicy())
	if err != nil {
		return nil, err
	}
	return &decision, nil
}
