package domain

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"
)

// StaffReasonMaxLength is the longest audited reason a staff write carries, in
// characters after trimming.
const StaffReasonMaxLength = 500

// StaffIdempotencyKeyMaxLength is the longest idempotency key a provisioning
// request carries, in characters after trimming.
const StaffIdempotencyKeyMaxLength = 128

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// StaffActor is the verified Keycloak staff caller behind one staff request.
// Subject is the staff subject the edge verified from the token, never a value
// from the request body. Reason is the audited reason of a write; a read leaves
// it empty.
type StaffActor struct {
	Subject string
	Reason  string
}

// StaffOrganization is an organization as staff see it.
type StaffOrganization struct {
	ID           string
	Name         string
	Slug         string
	Status       string
	CreatedAt    string
	MemberCount  int64
	OwnerUserIDs []string
}

// StaffMember is one membership of a staff-viewed organization.
type StaffMember struct {
	UserID   string
	Role     string
	Status   string
	JoinedAt string
}

// StaffInvite is a pending invitation without its token. Exactly one of Email
// and Phone is set.
type StaffInvite struct {
	ID        string
	Email     string
	Phone     string
	Role      string
	ExpiresAt string
}

// StaffProvisionRequest creates an organization with one pending owner
// invitation. Exactly one of OwnerEmail and OwnerPhone is set.
type StaffProvisionRequest struct {
	Name           string
	Slug           string
	OwnerEmail     string
	OwnerPhone     string
	IdempotencyKey string
	AcceptURL      string
}

// StaffProvisioned is the organization a provisioning call created, its owner
// invitation and, for a phone owner only, the raw invitation token. Token is a
// bearer secret: it is never logged.
type StaffProvisioned struct {
	Organization StaffOrganization
	OwnerInvite  StaffInvite
	Token        string
}

// StaffOrgDetail is one organization with its members and pending invitations.
type StaffOrgDetail struct {
	Organization   StaffOrganization
	Members        []StaffMember
	PendingInvites []StaffInvite
}

// StaffOwnerInviteRequest issues a new owner invitation for an organization.
// Exactly one of OwnerEmail and OwnerPhone is set.
type StaffOwnerInviteRequest struct {
	OrgID      string
	OwnerEmail string
	OwnerPhone string
	AcceptURL  string
}

// StaffOwnerInvite is a new owner invitation and, for a phone owner only, its
// raw token. Token is a bearer secret: it is never logged.
type StaffOwnerInvite struct {
	Invite StaffInvite
	Token  string
}

// StaffOrgService is the staff port over orbit-auth's StaffOrgService. Every
// call carries the service token configured on the edge, the actor's subject and,
// for writes, the actor's reason.
type StaffOrgService interface {
	ProvisionOrganization(ctx context.Context, actor StaffActor, in StaffProvisionRequest) (StaffProvisioned, error)
	GetOrganization(ctx context.Context, actor StaffActor, orgID string) (StaffOrgDetail, error)
	ReinviteOwner(ctx context.Context, actor StaffActor, in StaffOwnerInviteRequest) (StaffOwnerInvite, error)
}

// NormalizeStaffReason trims an audited reason and checks its length: 1 to
// StaffReasonMaxLength characters.
func NormalizeStaffReason(reason string) (string, error) {
	reason = strings.TrimSpace(reason)
	switch n := utf8.RuneCountInString(reason); {
	case n == 0:
		return "", NewError(KindInvalidArgument, "reason is required")
	case n > StaffReasonMaxLength:
		return "", NewError(KindInvalidArgument, "reason is too long")
	}
	return reason, nil
}

// NormalizeStaffIdempotencyKey trims an idempotency key and checks its length:
// 1 to StaffIdempotencyKeyMaxLength characters.
func NormalizeStaffIdempotencyKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	switch n := utf8.RuneCountInString(key); {
	case n == 0:
		return "", NewError(KindInvalidArgument, "idempotency_key is required")
	case n > StaffIdempotencyKeyMaxLength:
		return "", NewError(KindInvalidArgument, "idempotency_key is too long")
	}
	return key, nil
}

// NormalizeOwnerContact trims an owner's email and phone and requires exactly one
// of them.
func NormalizeOwnerContact(email, phone string) (string, string, error) {
	email = strings.TrimSpace(email)
	phone = strings.TrimSpace(phone)
	if (email == "") == (phone == "") {
		return "", "", NewError(KindInvalidArgument, "set exactly one of owner_email or owner_phone")
	}
	return email, phone, nil
}

// NormalizeStaffOrgID checks that an organization id is a UUID.
func NormalizeStaffOrgID(orgID string) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if !uuidPattern.MatchString(orgID) {
		return "", NewError(KindInvalidArgument, "org_id must be a UUID")
	}
	return orgID, nil
}
