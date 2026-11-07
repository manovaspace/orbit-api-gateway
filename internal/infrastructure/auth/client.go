// Package auth is the gRPC adapter for the upstream orbit-auth service. It maps
// the proto wire types to domain types and the gRPC status codes to domain
// error kinds, so nothing above this package imports the proto or gRPC.
package auth

import (
	"context"
	"net/http"
	"time"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Client implements domain.AuthService, domain.OrgService, domain.SignupService
// and domain.FlagSource over gRPC and orbit-auth's HTTP surface.
type Client struct {
	api    authv1.AuthServiceClient
	orgs   authv1.OrgServiceClient
	tenant authv1.TenantServiceClient
	signup authv1.SignupServiceClient
	conn   *grpc.ClientConn

	// AuthHTTPURL is the base URL of orbit-auth's HTTP listener. The flag
	// document is served there, not over gRPC.
	AuthHTTPURL string
	httpClient  *http.Client
}

var (
	_ domain.AuthService   = (*Client)(nil)
	_ domain.OrgService    = (*Client)(nil)
	_ domain.TenantService = (*Client)(nil)
	_ domain.SignupService = (*Client)(nil)
	_ domain.FlagSource    = (*Client)(nil)
)

// NewClient dials the upstream auth service. The caller closes the client.
func NewClient(addr string, opts ...grpc.DialOption) (*Client, error) {
	base := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	opts = append(base, opts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{
		api:        authv1.NewAuthServiceClient(conn),
		orgs:       authv1.NewOrgServiceClient(conn),
		tenant:     authv1.NewTenantServiceClient(conn),
		signup:     authv1.NewSignupServiceClient(conn),
		conn:       conn,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// RequestOTP asks orbit-auth to send a one-time password.
func (c *Client) RequestOTP(ctx context.Context, in domain.OTPRequest) (string, error) {
	resp, err := c.api.RequestOTP(ctx, &authv1.RequestOTPRequest{
		Identifier:    in.Identifier,
		Channel:       in.Channel,
		Email:         in.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		CorrelationId: in.CorrelationID,
	})
	if err != nil {
		return "", upstreamError(err)
	}
	return resp.GetExpiresAt(), nil
}

// VerifyOTP exchanges a one-time password for a token pair.
func (c *Client) VerifyOTP(ctx context.Context, in domain.OTPVerification) (domain.TokenPair, error) {
	resp, err := c.api.VerifyOTP(ctx, &authv1.VerifyOTPRequest{
		Identifier: in.Identifier,
		Channel:    in.Channel,
		Email:      in.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		Code:       in.Code,
	})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp.GetTokens()), nil
}

// LoginWithPassword exchanges a password for a token pair.
func (c *Client) LoginWithPassword(ctx context.Context, in domain.PasswordLogin) (domain.TokenPair, error) {
	resp, err := c.api.LoginWithPassword(ctx, &authv1.LoginWithPasswordRequest{
		Identifier: in.Identifier,
		Password:   in.Password,
	})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp), nil
}

// RefreshToken rotates a refresh token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (domain.TokenPair, error) {
	resp, err := c.api.RefreshToken(ctx, &authv1.RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp), nil
}

// ValidateAPIToken validates an oat_ API token and returns its identity.
func (c *Client) ValidateAPIToken(ctx context.Context, secret string) (domain.APIIdentity, error) {
	resp, err := c.api.ValidateApiToken(ctx, &authv1.ValidateApiTokenRequest{Secret: secret})
	if err != nil {
		return domain.APIIdentity{}, upstreamError(err)
	}
	return domain.APIIdentity{UserID: resp.GetUserId(), Scopes: resp.GetScopes()}, nil
}

// RegisterWithEmail starts a self-serve registration. The upstream answers an
// empty message for both a new and an existing address.
func (c *Client) RegisterWithEmail(ctx context.Context, in domain.SignupRegistration) error {
	_, err := c.signup.RegisterWithEmail(ctx, &authv1.RegisterWithEmailRequest{
		Email:       in.Email,
		Password:    in.Password,
		DisplayName: in.DisplayName,
		Locale:      in.Locale,
		OrgName:     in.OrgName,
		InviteToken: in.InviteToken,
	})
	if err != nil {
		return signupUpstreamError(err)
	}
	return nil
}

// VerifySignup exchanges a sign-up OTP and pending password for a token pair.
func (c *Client) VerifySignup(ctx context.Context, in domain.SignupVerification) (domain.TokenPair, error) {
	resp, err := c.signup.VerifySignup(ctx, &authv1.VerifySignupRequest{
		Email:    in.Email,
		Code:     in.Code,
		Password: in.Password,
	})
	if err != nil {
		return domain.TokenPair{}, signupUpstreamError(err)
	}
	return tokenPair(resp.GetTokens()), nil
}

// CreateOrg creates an organization owned by the caller.
func (c *Client) CreateOrg(ctx context.Context, name, slug, accessToken string) (domain.Organization, error) {
	resp, err := c.orgs.CreateOrg(callerContext(ctx, accessToken), &authv1.CreateOrgRequest{Name: name, Slug: slug})
	if err != nil {
		return domain.Organization{}, orgUpstreamError(err)
	}
	return organization(resp.GetOrganization()), nil
}

// SetOrgSlug renames an organization's slug.
func (c *Client) SetOrgSlug(ctx context.Context, orgID, slug, accessToken string) (domain.Organization, error) {
	resp, err := c.orgs.SetOrgSlug(callerContext(ctx, accessToken), &authv1.SetOrgSlugRequest{OrgId: orgID, Slug: slug})
	if err != nil {
		return domain.Organization{}, orgUpstreamError(err)
	}
	return organization(resp.GetOrganization()), nil
}

// ResolveTenant resolves a tenant host label through the unauthenticated
// TenantService. An unknown slug is a not-found error; every other failure is
// the generic upstream error so no detail reaches the edge's callers.
func (c *Client) ResolveTenant(ctx context.Context, slug string) (domain.Tenant, error) {
	resp, err := c.tenant.ResolveTenant(ctx, &authv1.ResolveTenantRequest{Slug: slug})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return domain.Tenant{}, domain.NewError(domain.KindNotFound, "tenant not found")
		}
		return domain.Tenant{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}
	return domain.Tenant{OrgID: resp.GetOrgId(), Name: resp.GetName(), Slug: resp.GetSlug(), Retired: resp.GetRetired()}, nil
}

// ListMyOrgs lists the organizations the caller belongs to.
func (c *Client) ListMyOrgs(ctx context.Context, accessToken string) ([]domain.Organization, error) {
	resp, err := c.orgs.ListMyOrgs(callerContext(ctx, accessToken), &authv1.ListMyOrgsRequest{})
	if err != nil {
		return nil, orgUpstreamError(err)
	}
	return organizations(resp.GetOrganizations()), nil
}

// ListMembers lists an organization's members.
func (c *Client) ListMembers(ctx context.Context, orgID, accessToken string) ([]domain.Membership, error) {
	resp, err := c.orgs.ListMembers(callerContext(ctx, accessToken), &authv1.ListMembersRequest{OrgId: orgID})
	if err != nil {
		return nil, orgUpstreamError(err)
	}
	return memberships(resp.GetMembers()), nil
}

// AddMember adds an existing user to an organization.
func (c *Client) AddMember(ctx context.Context, orgID, userID, accessToken string) error {
	_, err := c.orgs.AddMember(callerContext(ctx, accessToken), &authv1.AddMemberRequest{
		OrgId:  orgID,
		UserId: userID,
	})
	return orgUpstreamError(err)
}

// RemoveMember removes a user from an organization.
func (c *Client) RemoveMember(ctx context.Context, orgID, userID, accessToken string) error {
	_, err := c.orgs.RemoveMember(callerContext(ctx, accessToken), &authv1.RemoveMemberRequest{
		OrgId:  orgID,
		UserId: userID,
	})
	return orgUpstreamError(err)
}

// SuspendMember suspends a user's membership.
func (c *Client) SuspendMember(ctx context.Context, orgID, userID, accessToken string) error {
	_, err := c.orgs.SuspendMember(callerContext(ctx, accessToken), &authv1.SuspendMemberRequest{
		OrgId:  orgID,
		UserId: userID,
	})
	return orgUpstreamError(err)
}

// SetMemberRole changes a member's organization administration tier.
func (c *Client) SetMemberRole(ctx context.Context, orgID, userID, role, accessToken string) (domain.Membership, error) {
	resp, err := c.orgs.SetMemberRole(callerContext(ctx, accessToken), &authv1.SetMemberRoleRequest{
		OrgId:  orgID,
		UserId: userID,
		Role:   role,
	})
	if err != nil {
		return domain.Membership{}, orgUpstreamError(err)
	}
	return membership(resp.GetMembership()), nil
}

// InviteMember creates or rotates an organization invitation.
func (c *Client) InviteMember(ctx context.Context, orgID, email, accessToken string) (domain.Invite, error) {
	resp, err := c.orgs.InviteMember(callerContext(ctx, accessToken), &authv1.InviteMemberRequest{
		OrgId: orgID,
		Email: email,
	})
	if err != nil {
		return domain.Invite{}, orgUpstreamError(err)
	}
	return invite(resp.GetInvite()), nil
}

// AcceptInvite consumes an invitation token for the authenticated caller.
func (c *Client) AcceptInvite(ctx context.Context, token, accessToken string) (domain.Invite, error) {
	resp, err := c.orgs.AcceptInvite(callerContext(ctx, accessToken), &authv1.AcceptInviteRequest{Token: token})
	if err != nil {
		return domain.Invite{}, orgUpstreamError(err)
	}
	return invite(resp.GetInvite()), nil
}

// RevokeInvite revokes a pending invitation.
func (c *Client) RevokeInvite(ctx context.Context, orgID, inviteID, accessToken string) error {
	_, err := c.orgs.RevokeInvite(callerContext(ctx, accessToken), &authv1.RevokeInviteRequest{
		OrgId:    orgID,
		InviteId: inviteID,
	})
	if err != nil {
		return orgUpstreamError(err)
	}
	return nil
}

// ListInvites lists an organization's invitations.
func (c *Client) ListInvites(ctx context.Context, orgID, accessToken string) ([]domain.Invite, error) {
	resp, err := c.orgs.ListInvites(callerContext(ctx, accessToken), &authv1.ListInvitesRequest{OrgId: orgID})
	if err != nil {
		return nil, orgUpstreamError(err)
	}
	return invites(resp.GetInvites()), nil
}

// SelectOrg rotates the caller's refresh token and issues a pair carrying the
// selected organization.
func (c *Client) SelectOrg(ctx context.Context, orgID, refreshToken, accessToken string) (domain.TokenPair, error) {
	resp, err := c.orgs.SelectOrg(callerContext(ctx, accessToken), &authv1.SelectOrgRequest{
		OrgId:        orgID,
		RefreshToken: refreshToken,
	})
	if err != nil {
		return domain.TokenPair{}, orgUpstreamError(err)
	}
	return tokenPair(resp.GetTokens()), nil
}

// callerContext attaches the bearer access token the way orbit-auth's OrgService
// interceptor reads it: the first "authorization" metadata value.
func callerContext(ctx context.Context, accessToken string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+accessToken)
}

// Close closes the upstream connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func tokenPair(tokens *authv1.TokenResponse) domain.TokenPair {
	return domain.TokenPair{
		AccessToken:  tokens.GetAccessToken(),
		RefreshToken: tokens.GetRefreshToken(),
		ExpiresAt:    tokens.GetExpiresAt(),
	}
}

func organization(org *authv1.Organization) domain.Organization {
	return domain.Organization{
		ID:        org.GetId(),
		Name:      org.GetName(),
		Slug:      org.GetSlug(),
		CreatedAt: org.GetCreatedAt(),
		UpdatedAt: org.GetUpdatedAt(),
	}
}

func organizations(orgs []*authv1.Organization) []domain.Organization {
	out := make([]domain.Organization, 0, len(orgs))
	for _, org := range orgs {
		out = append(out, organization(org))
	}
	return out
}

func membership(in *authv1.Membership) domain.Membership {
	return domain.Membership{
		OrgID:     in.GetOrgId(),
		UserID:    in.GetUserId(),
		Status:    in.GetStatus(),
		Role:      in.GetRole(),
		CreatedAt: in.GetCreatedAt(),
		UpdatedAt: in.GetUpdatedAt(),
	}
}

func memberships(members []*authv1.Membership) []domain.Membership {
	out := make([]domain.Membership, 0, len(members))
	for _, member := range members {
		out = append(out, membership(member))
	}
	return out
}

func invite(in *authv1.Invite) domain.Invite {
	return domain.Invite{
		ID:         in.GetId(),
		OrgID:      in.GetOrgId(),
		Email:      in.GetEmail(),
		InviterID:  in.GetInviterId(),
		Status:     in.GetStatus(),
		ExpiresAt:  in.GetExpiresAt(),
		AcceptedAt: in.GetAcceptedAt(),
		CreatedAt:  in.GetCreatedAt(),
	}
}

func invites(items []*authv1.Invite) []domain.Invite {
	out := make([]domain.Invite, 0, len(items))
	for _, item := range items {
		out = append(out, invite(item))
	}
	return out
}

// upstreamError maps a gRPC failure to the domain kind the edge renders. Every
// code without a mapping keeps the single generic 500 body the edge has always
// returned, so an upstream internal detail never reaches a client verbatim.
func upstreamError(err error) error {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.InvalidArgument:
			return domain.NewError(domain.KindInvalidArgument, st.Message())
		case codes.Unauthenticated:
			return domain.NewError(domain.KindUnauthenticated, st.Message())
		case codes.PermissionDenied:
			return domain.NewError(domain.KindPermissionDenied, st.Message())
		case codes.FailedPrecondition:
			return domain.NewError(domain.KindFailedPrecondition, st.Message())
		case codes.ResourceExhausted:
			return domain.NewError(domain.KindResourceExhausted, st.Message())
		}
	}
	return domain.NewError(domain.KindInternal, "upstream error")
}

// orgUpstreamError is the mapping for organization and invitation calls. It
// keeps NotFound (including a non-member organization) distinct from an
// upstream failure, turns PermissionDenied (a member without organization
// administration authority) into a 403, and turns a failed precondition into a
// conflict so the edge answers 409. A nil error stays nil.
func orgUpstreamError(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.InvalidArgument:
			return domain.NewError(domain.KindInvalidArgument, st.Message())
		case codes.Unauthenticated:
			return domain.NewError(domain.KindUnauthenticated, st.Message())
		case codes.PermissionDenied:
			return domain.NewError(domain.KindPermissionDenied, st.Message())
		case codes.NotFound:
			return domain.NewError(domain.KindNotFound, st.Message())
		case codes.FailedPrecondition, codes.AlreadyExists:
			return domain.NewError(domain.KindConflict, st.Message())
		case codes.ResourceExhausted:
			return domain.NewError(domain.KindResourceExhausted, st.Message())
		}
	}
	return domain.NewError(domain.KindBadGateway, "upstream error")
}

// signupUpstreamError hides a disabled sign-up surface behind a 404, exactly as
// if the route did not exist. Every other failure follows orgUpstreamError.
func signupUpstreamError(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition {
		return domain.NewError(domain.KindNotFound, "not found")
	}
	return orgUpstreamError(err)
}
