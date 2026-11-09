package domain

import (
	"context"
	"strings"
)

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

// Organization administration tiers. A membership and an invitation both carry
// one of them.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Invite is an organization invitation without its secret token. Exactly one of
// Email and Phone is set.
type Invite struct {
	ID         string
	OrgID      string
	Email      string
	Phone      string
	Role       string
	InviterID  string
	Status     string
	ExpiresAt  string
	AcceptedAt string
	CreatedAt  string
}

// InviteRequest is one invitation to an email address or a phone number. Exactly
// one of Email and Phone is set. Role is owner, admin or member; empty means
// member.
type InviteRequest struct {
	OrgID string
	Email string
	Phone string
	Role  string
}

// CreatedInvite is the result of an invitation write. Token is the raw invitation
// token. orbit-auth returns it only for a phone invitation, which has no email to
// carry it, and it is empty otherwise. It is a bearer secret: it is never logged.
type CreatedInvite struct {
	Invite Invite
	Token  string
}

// NormalizeInviteRequest checks an invitation request before orbit-auth sees it.
// Surrounding spaces are trimmed, exactly one of Email and Phone must remain, and
// an empty role becomes member. Any role other than owner, admin or member is
// refused.
func NormalizeInviteRequest(in InviteRequest) (InviteRequest, error) {
	in.Email = strings.TrimSpace(in.Email)
	in.Phone = strings.TrimSpace(in.Phone)
	if (in.Email == "") == (in.Phone == "") {
		return InviteRequest{}, NewError(KindInvalidArgument, "set exactly one of email or phone")
	}
	in.Role = strings.TrimSpace(in.Role)
	switch in.Role {
	case "":
		in.Role = RoleMember
	case RoleOwner, RoleAdmin, RoleMember:
	default:
		return InviteRequest{}, NewError(KindInvalidArgument, "role must be owner, admin or member")
	}
	return in, nil
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
	InviteMember(ctx context.Context, in InviteRequest, accessToken string) (CreatedInvite, error)
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
