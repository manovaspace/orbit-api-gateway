package domain

import "context"

// Organization is one tenant returned by orbit-auth.
type Organization struct {
	ID   string
	Name string
	// Slug is the organization's current tenant host label.
	Slug      string
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
	CreateOrg(ctx context.Context, name, slug, accessToken string) (Organization, error)
	SetOrgSlug(ctx context.Context, orgID, slug, accessToken string) (Organization, error)
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

// Tenant is what the edge may say about a tenant host before anyone signs in:
// the organization id, its name and its current slug. Retired reports that the
// requested slug is no longer the current one, so the caller can redirect.
type Tenant struct {
	OrgID   string
	Name    string
	Slug    string
	Retired bool
}

// TenantService resolves a tenant host label without authentication, over
// orbit-auth's TenantService.
type TenantService interface {
	// ResolveTenant returns the tenant for slug, or a not-found error for an
	// unknown, invalid or reserved slug.
	ResolveTenant(ctx context.Context, slug string) (Tenant, error)
}
