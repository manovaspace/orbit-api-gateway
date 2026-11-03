package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// RegisterWithEmail starts a self-serve registration. The upstream response is
// deliberately empty: the edge answers the same for a new and an existing
// address.
func (s *Service) RegisterWithEmail(ctx context.Context, in domain.SignupRegistration) error {
	return s.signup.RegisterWithEmail(ctx, in)
}

// VerifySignup exchanges the sign-up OTP and pending password for a token pair.
func (s *Service) VerifySignup(ctx context.Context, in domain.SignupVerification) (domain.TokenPair, error) {
	return s.signup.VerifySignup(ctx, in)
}

// CreateOrg creates an organization owned by the caller.
func (s *Service) CreateOrg(ctx context.Context, name, accessToken string) (domain.Organization, error) {
	return s.orgs.CreateOrg(ctx, name, accessToken)
}

// ListMyOrgs lists the organizations the caller belongs to.
func (s *Service) ListMyOrgs(ctx context.Context, accessToken string) ([]domain.Organization, error) {
	return s.orgs.ListMyOrgs(ctx, accessToken)
}

// ListMembers lists an organization's members.
func (s *Service) ListMembers(ctx context.Context, orgID, accessToken string) ([]domain.Membership, error) {
	return s.orgs.ListMembers(ctx, orgID, accessToken)
}

// AddMember adds an existing user to an organization.
func (s *Service) AddMember(ctx context.Context, orgID, userID, accessToken string) error {
	return s.orgs.AddMember(ctx, orgID, userID, accessToken)
}

// RemoveMember removes a user from an organization. Orbit Auth refuses to
// remove the last active member.
func (s *Service) RemoveMember(ctx context.Context, orgID, userID, accessToken string) error {
	return s.orgs.RemoveMember(ctx, orgID, userID, accessToken)
}

// SuspendMember suspends a user's membership without deleting it.
func (s *Service) SuspendMember(ctx context.Context, orgID, userID, accessToken string) error {
	return s.orgs.SuspendMember(ctx, orgID, userID, accessToken)
}

// InviteMember creates or rotates an organization invitation.
func (s *Service) InviteMember(ctx context.Context, orgID, email, accessToken string) (domain.Invite, error) {
	return s.orgs.InviteMember(ctx, orgID, email, accessToken)
}

// AcceptInvite consumes an invitation token for the authenticated caller.
func (s *Service) AcceptInvite(ctx context.Context, token, accessToken string) (domain.Invite, error) {
	return s.orgs.AcceptInvite(ctx, token, accessToken)
}

// RevokeInvite revokes a pending invitation.
func (s *Service) RevokeInvite(ctx context.Context, orgID, inviteID, accessToken string) error {
	return s.orgs.RevokeInvite(ctx, orgID, inviteID, accessToken)
}

// ListInvites lists an organization's invitations.
func (s *Service) ListInvites(ctx context.Context, orgID, accessToken string) ([]domain.Invite, error) {
	return s.orgs.ListInvites(ctx, orgID, accessToken)
}

// SelectOrg rotates the caller's refresh token and issues a pair carrying the
// selected organization.
func (s *Service) SelectOrg(ctx context.Context, orgID, refreshToken, accessToken string) (domain.TokenPair, error) {
	return s.orgs.SelectOrg(ctx, orgID, refreshToken, accessToken)
}

// CheckKeyLimit applies a precomputed bucket key and policy. It is the entry
// point for routes whose key is not an OTP identifier or a per-class client
// key, such as per-IP signup and per-organization buckets.
func (s *Service) CheckKeyLimit(ctx context.Context, key string, policy domain.Policy) (domain.Decision, error) {
	return s.allow(ctx, key, policy)
}
