package application

import (
	"context"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// ProvisionStaffOrg creates an organization for a staff caller. The reason, the
// owner contact and the idempotency key are checked here, before orbit-auth sees
// them.
func (s *Service) ProvisionStaffOrg(ctx context.Context, actor domain.StaffActor, in domain.StaffProvisionRequest) (domain.StaffProvisioned, error) {
	reason, err := domain.NormalizeStaffReason(actor.Reason)
	if err != nil {
		return domain.StaffProvisioned{}, err
	}
	email, phone, err := domain.NormalizeOwnerContact(in.OwnerEmail, in.OwnerPhone)
	if err != nil {
		return domain.StaffProvisioned{}, err
	}
	key, err := domain.NormalizeStaffIdempotencyKey(in.IdempotencyKey)
	if err != nil {
		return domain.StaffProvisioned{}, err
	}
	acceptURL, err := domain.NormalizeAcceptURL(in.AcceptURL)
	if err != nil {
		return domain.StaffProvisioned{}, err
	}
	in.AcceptURL = acceptURL
	actor.Reason = reason
	in.Name = strings.TrimSpace(in.Name)
	in.Slug = strings.TrimSpace(in.Slug)
	in.OwnerEmail, in.OwnerPhone, in.IdempotencyKey = email, phone, key
	return s.staffOrgs.ProvisionOrganization(ctx, actor, in)
}

// GetStaffOrg returns one organization with its members and pending invitations.
// A read carries no reason.
func (s *Service) GetStaffOrg(ctx context.Context, subject, orgID string) (domain.StaffOrgDetail, error) {
	id, err := domain.NormalizeStaffOrgID(orgID)
	if err != nil {
		return domain.StaffOrgDetail{}, err
	}
	return s.staffOrgs.GetOrganization(ctx, domain.StaffActor{Subject: subject}, id)
}

// ReinviteStaffOwner issues a new owner invitation for an organization. The
// reason, the organization id and the owner contact are checked here.
func (s *Service) ReinviteStaffOwner(ctx context.Context, actor domain.StaffActor, in domain.StaffOwnerInviteRequest) (domain.StaffOwnerInvite, error) {
	reason, err := domain.NormalizeStaffReason(actor.Reason)
	if err != nil {
		return domain.StaffOwnerInvite{}, err
	}
	id, err := domain.NormalizeStaffOrgID(in.OrgID)
	if err != nil {
		return domain.StaffOwnerInvite{}, err
	}
	email, phone, err := domain.NormalizeOwnerContact(in.OwnerEmail, in.OwnerPhone)
	if err != nil {
		return domain.StaffOwnerInvite{}, err
	}
	acceptURL, err := domain.NormalizeAcceptURL(in.AcceptURL)
	if err != nil {
		return domain.StaffOwnerInvite{}, err
	}
	actor.Reason = reason
	in.OrgID, in.OwnerEmail, in.OwnerPhone, in.AcceptURL = id, email, phone, acceptURL
	return s.staffOrgs.ReinviteOwner(ctx, actor, in)
}
