package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// GetInvitePreview shows what an invitation token grants before sign-in. It never
// returns the recipient.
func (s *Service) GetInvitePreview(ctx context.Context, token string) (domain.InvitePreview, error) {
	return s.invites.GetInvitePreview(ctx, token)
}

// AcceptInviteWithSignup creates the account for a phone invitation and joins its
// organization.
func (s *Service) AcceptInviteWithSignup(ctx context.Context, in domain.InviteSignup) (domain.InviteAcceptance, error) {
	return s.invites.AcceptInviteWithSignup(ctx, in)
}
