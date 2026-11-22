package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Metadata keys of the staff surface. Every call carries the service token and
// the staff subject; a write also carries the reason, as binary metadata.
const (
	staffServiceTokenKey = "x-orbit-service-token"
	staffSubjectKey      = "x-staff-subject"
	staffReasonKey       = "x-staff-reason-bin"
)

// ProvisionOrganization creates an organization with one pending owner invitation.
func (c *Client) ProvisionOrganization(ctx context.Context, actor domain.StaffActor, in domain.StaffProvisionRequest) (domain.StaffProvisioned, error) {
	resp, err := c.staff.ProvisionOrganization(c.staffContext(ctx, actor, true), &authv1.ProvisionOrganizationRequest{
		Name:           in.Name,
		Slug:           in.Slug,
		OwnerEmail:     in.OwnerEmail,
		OwnerPhone:     in.OwnerPhone,
		IdempotencyKey: in.IdempotencyKey,
		AcceptUrl:      in.AcceptURL,
	})
	if err != nil {
		return domain.StaffProvisioned{}, staffUpstreamError(err)
	}
	return domain.StaffProvisioned{
		Organization: staffOrganization(resp.GetOrganization()),
		OwnerInvite:  staffInvite(resp.GetOwnerInvite()),
		Token:        resp.GetToken(),
	}, nil
}

// GetOrganization returns one organization with its members and pending invitations.
func (c *Client) GetOrganization(ctx context.Context, actor domain.StaffActor, orgID string) (domain.StaffOrgDetail, error) {
	resp, err := c.staff.GetOrganization(c.staffContext(ctx, actor, false), &authv1.GetOrganizationRequest{OrgId: orgID})
	if err != nil {
		return domain.StaffOrgDetail{}, staffUpstreamError(err)
	}
	detail := domain.StaffOrgDetail{Organization: staffOrganization(resp.GetOrganization())}
	for _, member := range resp.GetMembers() {
		detail.Members = append(detail.Members, domain.StaffMember{
			UserID:   member.GetUserId(),
			Role:     member.GetRole(),
			Status:   member.GetStatus(),
			JoinedAt: member.GetJoinedAt(),
		})
	}
	for _, invite := range resp.GetPendingInvites() {
		detail.PendingInvites = append(detail.PendingInvites, staffInvite(invite))
	}
	return detail, nil
}

// ReinviteOwner issues a new owner invitation. The raw token comes back only for a
// phone invitation.
func (c *Client) ReinviteOwner(ctx context.Context, actor domain.StaffActor, in domain.StaffOwnerInviteRequest) (domain.StaffOwnerInvite, error) {
	resp, err := c.staff.ReinviteOwner(c.staffContext(ctx, actor, true), &authv1.ReinviteOwnerRequest{
		OrgId:      in.OrgID,
		OwnerEmail: in.OwnerEmail,
		OwnerPhone: in.OwnerPhone,
		AcceptUrl:  in.AcceptURL,
	})
	if err != nil {
		return domain.StaffOwnerInvite{}, staffUpstreamError(err)
	}
	return domain.StaffOwnerInvite{Invite: staffInvite(resp.GetInvite()), Token: resp.GetToken()}, nil
}

// staffContext attaches the service token and the staff subject to the outgoing
// call, and the reason too for a write.
func (c *Client) staffContext(ctx context.Context, actor domain.StaffActor, write bool) context.Context {
	pairs := []string{staffServiceTokenKey, c.StaffServiceToken, staffSubjectKey, actor.Subject}
	if write {
		pairs = append(pairs, staffReasonKey, actor.Reason)
	}
	return metadata.AppendToOutgoingContext(ctx, pairs...)
}

// staffUpstreamError maps a staff call failure. An unconfigured or refused service
// token answers 502 and an unavailable staff service 503, both with a fixed message:
// the upstream detail never reaches the client.
func staffUpstreamError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return domain.NewError(domain.KindBadGateway, "upstream error")
	}
	switch st.Code() {
	case codes.InvalidArgument:
		return domain.NewError(domain.KindInvalidArgument, st.Message())
	case codes.NotFound:
		return domain.NewError(domain.KindNotFound, st.Message())
	case codes.AlreadyExists, codes.FailedPrecondition:
		return domain.NewError(domain.KindConflict, st.Message())
	case codes.Unavailable:
		return domain.NewError(domain.KindUnavailable, "staff service unavailable")
	}
	return domain.NewError(domain.KindBadGateway, "upstream error")
}

func staffOrganization(org *authv1.StaffOrganization) domain.StaffOrganization {
	return domain.StaffOrganization{
		ID:           org.GetId(),
		Name:         org.GetName(),
		Slug:         org.GetSlug(),
		Status:       org.GetStatus(),
		CreatedAt:    org.GetCreatedAt(),
		MemberCount:  org.GetMemberCount(),
		OwnerUserIDs: org.GetOwnerUserIds(),
	}
}

func staffInvite(in *authv1.StaffInvite) domain.StaffInvite {
	return domain.StaffInvite{
		ID:        in.GetId(),
		Email:     in.GetEmail(),
		Phone:     in.GetPhone(),
		Role:      in.GetRole(),
		ExpiresAt: in.GetExpiresAt(),
	}
}
