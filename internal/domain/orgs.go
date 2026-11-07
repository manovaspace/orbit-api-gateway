package domain

import "context"

// Organization is one tenant returned by orbit-auth.
type Organization struct {
	ID        string
	Name      string
	CreatedAt string
	UpdatedAt string
}

// Membership is one user's membership in an organization.
type Membership struct {
	OrgID  string
	UserID string
	Status string
	// Role is the organization administration tier: owner, admin or member.
	Role      string
	CreatedAt string
	UpdatedAt string
}

// Invite is an organization invitation without its secret token.
type Invite struct {
	ID         string
	OrgID      string
	Email      string
	InviterID  string
	Status     string
	ExpiresAt  string
	AcceptedAt string
	CreatedAt  string
}

// OrgService is the organization and invitation port over orbit-auth's
// OrgService. The access token is the caller's bearer token; orbit-auth
// verifies it and derives the acting user from it, never from the request.
type OrgService interface {
	CreateOrg(ctx context.Context, name, accessToken string) (Organization, error)
	ListMyOrgs(ctx context.Context, accessToken string) ([]Organization, error)
	ListMembers(ctx context.Context, orgID, accessToken string) ([]Membership, error)
	AddMember(ctx context.Context, orgID, userID, accessToken string) error
	RemoveMember(ctx context.Context, orgID, userID, accessToken string) error
	SuspendMember(ctx context.Context, orgID, userID, accessToken string) error
	SetMemberRole(ctx context.Context, orgID, userID, role, accessToken string) (Membership, error)
	InviteMember(ctx context.Context, orgID, email, accessToken string) (Invite, error)
	AcceptInvite(ctx context.Context, token, accessToken string) (Invite, error)
	RevokeInvite(ctx context.Context, orgID, inviteID, accessToken string) error
	ListInvites(ctx context.Context, orgID, accessToken string) ([]Invite, error)
	SelectOrg(ctx context.Context, orgID, refreshToken, accessToken string) (TokenPair, error)
}
