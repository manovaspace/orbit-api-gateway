package domain

import "context"

// InvitePreview is what the holder of an invitation token may see before signing
// in. It carries no recipient.
type InvitePreview struct {
	OrgID     string
	OrgName   string
	OrgSlug   string
	Role      string
	ExpiresAt string
}

// InviteSignup creates the account for a phone invitation. Token is the raw
// invitation token; it is a bearer secret and is never logged.
type InviteSignup struct {
	Token       string
	Password    string
	DisplayName string
}

// InviteAcceptance is the account a phone invitation created and the organization
// it joined.
type InviteAcceptance struct {
	UserID string
	OrgID  string
}

// InviteService is the public invitation port over orbit-auth's InviteService.
// The invitee has no session yet, so the invitation token is the only credential.
// Every token that cannot be used is reported as the same not-found error.
type InviteService interface {
	// GetInvitePreview returns what a pending, unexpired invitation grants.
	GetInvitePreview(ctx context.Context, token string) (InvitePreview, error)
	// AcceptInviteWithSignup creates the account for a phone invitation and joins
	// its organization.
	AcceptInviteWithSignup(ctx context.Context, in InviteSignup) (InviteAcceptance, error)
}
