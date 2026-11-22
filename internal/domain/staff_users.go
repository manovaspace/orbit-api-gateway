package domain

import (
	"context"
	"strings"
)

// StaffUser is an account as staff see it. It never carries a password hash, a
// token or a hash of either. Optional times are empty when absent.
type StaffUser struct {
	ID              string
	Email           string
	Mobile          string
	Username        string
	DisplayName     string
	Status          string
	EmailVerified   bool
	MobileVerified  bool
	HasPassword     bool
	GoogleLinked    bool
	CreatedAt       string
	LastLoginAt     string
	DisabledAt      string
	DisabledReason  string
	MembershipCount int64
}

// StaffUserMembership is one organization membership of an account.
type StaffUserMembership struct {
	OrgID     string
	OrgName   string
	OrgSlug   string
	OrgStatus string
	Role      string
	Status    string
	JoinedAt  string
}

// StaffUserDetail is one account with its organization memberships.
type StaffUserDetail struct {
	User        StaffUser
	Memberships []StaffUserMembership
}

// StaffUserListRequest pages through accounts. Zero PageSize means the upstream
// default.
type StaffUserListRequest struct {
	Query     string
	Status    string
	PageToken string
	PageSize  int32
}

// StaffUserPage is one page of accounts. NextPageToken is empty on the last page.
type StaffUserPage struct {
	Users         []StaffUser
	NextPageToken string
}

// StaffAuditEvent is one durable audit row. Details is a JSON object as text and
// never holds an email address, a mobile number, a password, a token or a hash.
type StaffAuditEvent struct {
	ID            int64
	OccurredAt    string
	Action        string
	ActorKind     string
	ActorID       string
	OrgID         string
	SubjectUserID string
	InviteID      string
	Reason        string
	Details       string
}

// StaffAuditEventListRequest pages through audit rows. At least one of OrgID and
// UserID is set.
type StaffAuditEventListRequest struct {
	OrgID     string
	UserID    string
	PageToken string
	PageSize  int32
}

// StaffAuditEventPage is one page of audit rows. NextPageToken is empty on the
// last page.
type StaffAuditEventPage struct {
	Events        []StaffAuditEvent
	NextPageToken string
}

// StaffUserService is the staff port over orbit-auth's StaffUserService. Every
// call carries the service token configured on the edge and the actor's subject;
// a write also carries the actor's reason.
type StaffUserService interface {
	ListUsers(ctx context.Context, actor StaffActor, in StaffUserListRequest) (StaffUserPage, error)
	GetUser(ctx context.Context, actor StaffActor, userID string) (StaffUserDetail, error)
	// DisableUser reports changed=false when the account was already disabled.
	DisableUser(ctx context.Context, actor StaffActor, userID string) (bool, error)
	// EnableUser reports changed=false when the account was already active.
	EnableUser(ctx context.Context, actor StaffActor, userID string) (bool, error)
	ListAuditEvents(ctx context.Context, actor StaffActor, in StaffAuditEventListRequest) (StaffAuditEventPage, error)
}

// NormalizeStaffUserID checks that an account id is a UUID.
func NormalizeStaffUserID(userID string) (string, error) {
	userID = strings.TrimSpace(userID)
	if !uuidPattern.MatchString(userID) {
		return "", NewError(KindInvalidArgument, "user_id must be a UUID")
	}
	return userID, nil
}
