package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// ListUsers pages through accounts. A read carries no reason.
func (c *Client) ListUsers(ctx context.Context, actor domain.StaffActor, in domain.StaffUserListRequest) (domain.StaffUserPage, error) {
	resp, err := c.users.ListUsers(c.staffContext(ctx, actor, false), &authv1.ListUsersRequest{
		Query:     in.Query,
		Status:    in.Status,
		PageSize:  in.PageSize,
		PageToken: in.PageToken,
	})
	if err != nil {
		return domain.StaffUserPage{}, staffUpstreamError(err)
	}
	page := domain.StaffUserPage{NextPageToken: resp.GetNextPageToken()}
	for _, user := range resp.GetUsers() {
		page.Users = append(page.Users, staffUser(user))
	}
	return page, nil
}

// GetUser returns one account with its memberships.
func (c *Client) GetUser(ctx context.Context, actor domain.StaffActor, userID string) (domain.StaffUserDetail, error) {
	resp, err := c.users.GetUser(c.staffContext(ctx, actor, false), &authv1.GetUserRequest{UserId: userID})
	if err != nil {
		return domain.StaffUserDetail{}, staffUpstreamError(err)
	}
	detail := domain.StaffUserDetail{User: staffUser(resp.GetUser())}
	for _, m := range resp.GetMemberships() {
		detail.Memberships = append(detail.Memberships, domain.StaffUserMembership{
			OrgID:     m.GetOrgId(),
			OrgName:   m.GetOrgName(),
			OrgSlug:   m.GetOrgSlug(),
			OrgStatus: m.GetOrgStatus(),
			Role:      m.GetRole(),
			Status:    m.GetStatus(),
			JoinedAt:  m.GetJoinedAt(),
		})
	}
	return detail, nil
}

// DisableUser disables an active account. The reason travels as metadata.
func (c *Client) DisableUser(ctx context.Context, actor domain.StaffActor, userID string) (bool, error) {
	resp, err := c.users.DisableUser(c.staffContext(ctx, actor, true), &authv1.DisableUserRequest{UserId: userID})
	if err != nil {
		return false, staffUpstreamError(err)
	}
	return resp.GetChanged(), nil
}

// EnableUser enables a disabled account. The reason travels as metadata.
func (c *Client) EnableUser(ctx context.Context, actor domain.StaffActor, userID string) (bool, error) {
	resp, err := c.users.EnableUser(c.staffContext(ctx, actor, true), &authv1.EnableUserRequest{UserId: userID})
	if err != nil {
		return false, staffUpstreamError(err)
	}
	return resp.GetChanged(), nil
}

// ListAuditEvents pages through audit rows. A read carries no reason.
func (c *Client) ListAuditEvents(ctx context.Context, actor domain.StaffActor, in domain.StaffAuditEventListRequest) (domain.StaffAuditEventPage, error) {
	resp, err := c.users.ListAuditEvents(c.staffContext(ctx, actor, false), &authv1.ListAuditEventsRequest{
		OrgId:     in.OrgID,
		UserId:    in.UserID,
		PageSize:  in.PageSize,
		PageToken: in.PageToken,
	})
	if err != nil {
		return domain.StaffAuditEventPage{}, staffUpstreamError(err)
	}
	page := domain.StaffAuditEventPage{NextPageToken: resp.GetNextPageToken()}
	for _, ev := range resp.GetEvents() {
		page.Events = append(page.Events, domain.StaffAuditEvent{
			ID:            ev.GetId(),
			OccurredAt:    ev.GetOccurredAt(),
			Action:        ev.GetAction(),
			ActorKind:     ev.GetActorKind(),
			ActorID:       ev.GetActorId(),
			OrgID:         ev.GetOrgId(),
			SubjectUserID: ev.GetSubjectUserId(),
			InviteID:      ev.GetInviteId(),
			Reason:        ev.GetReason(),
			Details:       ev.GetDetails(),
		})
	}
	return page, nil
}

func staffUser(u *authv1.StaffUser) domain.StaffUser {
	return domain.StaffUser{
		ID:              u.GetId(),
		Email:           u.GetEmail(),
		Mobile:          u.GetMobile(),
		Username:        u.GetUsername(),
		DisplayName:     u.GetDisplayName(),
		Status:          u.GetStatus(),
		EmailVerified:   u.GetEmailVerified(),
		MobileVerified:  u.GetMobileVerified(),
		HasPassword:     u.GetHasPassword(),
		GoogleLinked:    u.GetGoogleLinked(),
		CreatedAt:       u.GetCreatedAt(),
		LastLoginAt:     u.GetLastLoginAt(),
		DisabledAt:      u.GetDisabledAt(),
		DisabledReason:  u.GetDisabledReason(),
		MembershipCount: u.GetMembershipCount(),
	}
}
