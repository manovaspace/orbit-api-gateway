package application

import (
	"context"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// staffUserPageSizeMax is the largest page a staff account or audit listing asks
// for. Zero means the upstream default page size.
const staffUserPageSizeMax = 100

// ListStaffUsers pages through accounts. A read carries no reason.
func (s *Service) ListStaffUsers(ctx context.Context, subject string, in domain.StaffUserListRequest) (domain.StaffUserPage, error) {
	if in.PageSize < 0 || in.PageSize > staffUserPageSizeMax {
		return domain.StaffUserPage{}, domain.NewError(domain.KindInvalidArgument, "page_size must be between 0 and 100")
	}
	return s.staffUsers.ListUsers(ctx, domain.StaffActor{Subject: subject}, in)
}

// GetStaffUser returns one account with its organization memberships.
func (s *Service) GetStaffUser(ctx context.Context, subject, userID string) (domain.StaffUserDetail, error) {
	id, err := domain.NormalizeStaffUserID(userID)
	if err != nil {
		return domain.StaffUserDetail{}, err
	}
	return s.staffUsers.GetUser(ctx, domain.StaffActor{Subject: subject}, id)
}

// DisableStaffUser disables an account and returns it as it is afterwards. The
// reason is checked here, before orbit-auth sees it.
func (s *Service) DisableStaffUser(ctx context.Context, actor domain.StaffActor, userID string) (domain.StaffUser, error) {
	return s.changeStaffUser(ctx, actor, userID, s.staffUsers.DisableUser)
}

// EnableStaffUser enables an account and returns it as it is afterwards. The
// reason is checked here, before orbit-auth sees it.
func (s *Service) EnableStaffUser(ctx context.Context, actor domain.StaffActor, userID string) (domain.StaffUser, error) {
	return s.changeStaffUser(ctx, actor, userID, s.staffUsers.EnableUser)
}

// changeStaffUser runs one account write and reads the account back, since the
// upstream write answers only whether it changed anything.
func (s *Service) changeStaffUser(ctx context.Context, actor domain.StaffActor, userID string,
	write func(context.Context, domain.StaffActor, string) (bool, error)) (domain.StaffUser, error) {
	reason, err := domain.NormalizeStaffReason(actor.Reason)
	if err != nil {
		return domain.StaffUser{}, err
	}
	id, err := domain.NormalizeStaffUserID(userID)
	if err != nil {
		return domain.StaffUser{}, err
	}
	actor.Reason = reason
	if _, err := write(ctx, actor, id); err != nil {
		return domain.StaffUser{}, err
	}
	detail, err := s.staffUsers.GetUser(ctx, domain.StaffActor{Subject: actor.Subject}, id)
	if err != nil {
		return domain.StaffUser{}, err
	}
	return detail.User, nil
}

// ListStaffAuditEvents pages through audit rows. At least one of the organization
// and the user must be named; a read carries no reason.
func (s *Service) ListStaffAuditEvents(ctx context.Context, subject string, in domain.StaffAuditEventListRequest) (domain.StaffAuditEventPage, error) {
	if in.OrgID == "" && in.UserID == "" {
		return domain.StaffAuditEventPage{}, domain.NewError(domain.KindInvalidArgument, "org_id or user_id is required")
	}
	if in.PageSize < 0 || in.PageSize > staffUserPageSizeMax {
		return domain.StaffAuditEventPage{}, domain.NewError(domain.KindInvalidArgument, "page_size must be between 0 and 100")
	}
	if in.OrgID != "" {
		id, err := domain.NormalizeStaffOrgID(in.OrgID)
		if err != nil {
			return domain.StaffAuditEventPage{}, err
		}
		in.OrgID = id
	}
	if in.UserID != "" {
		id, err := domain.NormalizeStaffUserID(in.UserID)
		if err != nil {
			return domain.StaffAuditEventPage{}, err
		}
		in.UserID = id
	}
	return s.staffUsers.ListAuditEvents(ctx, domain.StaffActor{Subject: subject}, in)
}
