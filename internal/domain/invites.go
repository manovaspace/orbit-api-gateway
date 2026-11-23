package domain

import (
	"context"
	"strings"
	"unicode/utf8"
)

// AcceptURLMaxLength is the longest accept_url the edge forwards, in characters
// after trimming. orbit-auth validates the URL itself.
const AcceptURLMaxLength = 500

// NormalizeAcceptURL trims an optional acceptance-page URL and bounds its length.
// An empty value is valid: the invitation then carries only the code.
func NormalizeAcceptURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if utf8.RuneCountInString(raw) > AcceptURLMaxLength {
		return "", NewError(KindInvalidArgument, "accept_url is too long")
	}
	return raw, nil
}

// InvitePreview is what the holder of an invitation token may see before signing
// in. It carries no recipient.
type InvitePreview struct {
	OrgID     string
	OrgName   string
	OrgSlug   string
	Role      string
	ExpiresAt string
	// Channel is how the invitation was delivered: "email" or "phone".
	Channel string
	// AccountExists reports that an active account already uses the invited
	// phone number or email. It never says whose account it is.
	AccountExists bool
}

// InviteSignup creates the account for a phone invitation. Token is the raw
// invitation token; it is a bearer secret and is never logged.
type InviteSignup struct {
	Token       string
	Password    string
	DisplayName string
	// PhoneCode is the one-time code RequestInvitePhoneCode sent to the invited
	// number. Required for a phone invitation; ignored for an email invitation.
	PhoneCode string
}

// InviteAcceptance is the account a phone invitation created and the organization
// it joined.
type InviteAcceptance struct {
	UserID   string
	OrgID    string
	InviteID string
	Role     string
	// Identifier is what the new account signs in with: its phone in E.164 form,
	// or its email address.
	Identifier string
}

// InviteService is the public invitation port over orbit-auth's InviteService.
// The invitee has no session yet, so the invitation token is the only credential.
// Every token that cannot be used is reported as the same not-found error.
type InviteService interface {
	// GetInvitePreview returns what a pending, unexpired invitation grants.
	GetInvitePreview(ctx context.Context, token string) (InvitePreview, error)
	// RequestInvitePhoneCode sends the one-time code for a phone invitation and
	// returns when the code stops being valid, as an RFC 3339 string.
	RequestInvitePhoneCode(ctx context.Context, token string) (expiresAt string, err error)
	// AcceptInviteWithSignup creates the account for a phone invitation and joins
	// its organization.
	AcceptInviteWithSignup(ctx context.Context, in InviteSignup) (InviteAcceptance, error)
}
