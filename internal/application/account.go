package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// maxInviteTokenBytes bounds the invitation token a Google sign-in may carry.
const maxInviteTokenBytes = 512

// GetSignInMethods returns how the caller's account signs in.
func (s *Service) GetSignInMethods(ctx context.Context, accessToken string) (domain.SignInMethods, error) {
	return s.accounts.GetSignInMethods(ctx, accessToken)
}

// SetPassword sets or changes the caller's password. The passwords are checked
// upstream; the edge forwards them unchanged.
func (s *Service) SetPassword(ctx context.Context, in domain.SetPasswordRequest, accessToken string) error {
	return s.accounts.SetPassword(ctx, in, accessToken)
}

// StartGoogleLink begins linking a Google account to the caller.
func (s *Service) StartGoogleLink(ctx context.Context, in domain.GoogleLinkStart, accessToken string) (domain.GoogleLinkStarted, error) {
	return s.accounts.StartGoogleLink(ctx, in, accessToken)
}

// CompleteGoogleLink finishes a Google link. It issues no tokens.
func (s *Service) CompleteGoogleLink(ctx context.Context, in domain.GoogleLinkComplete, accessToken string) (domain.GoogleLinked, error) {
	return s.accounts.CompleteGoogleLink(ctx, in, accessToken)
}

// UnlinkGoogle removes the caller's Google account.
func (s *Service) UnlinkGoogle(ctx context.Context, accessToken string) error {
	return s.accounts.UnlinkGoogle(ctx, accessToken)
}

// RevokeAllSessions revokes the caller's refresh tokens, except refreshToken
// when it is given.
func (s *Service) RevokeAllSessions(ctx context.Context, refreshToken, accessToken string) error {
	return s.accounts.RevokeAllSessions(ctx, refreshToken, accessToken)
}
