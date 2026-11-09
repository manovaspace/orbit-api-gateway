package auth

import (
	"context"
	"net"
	"testing"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

type orgSignupStub struct {
	authv1.UnimplementedOrgServiceServer
	authv1.UnimplementedTenantServiceServer
	authv1.UnimplementedSignupServiceServer
	authv1.UnimplementedInviteServiceServer
	err           error
	authorization string
	inviteReq     *authv1.InviteMemberRequest
	signupReq     *authv1.AcceptInviteWithSignupRequest
	previewToken  string
}

func (s *orgSignupStub) record(ctx context.Context) error {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("authorization"); len(values) > 0 {
			s.authorization = values[0]
		}
	}
	return s.err
}

func (s *orgSignupStub) CreateOrg(ctx context.Context, in *authv1.CreateOrgRequest) (*authv1.CreateOrgResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.CreateOrgResponse{Organization: &authv1.Organization{Id: "org-" + in.GetName(), Name: in.GetName()}}, nil
}

func (s *orgSignupStub) ListMyOrgs(ctx context.Context, _ *authv1.ListMyOrgsRequest) (*authv1.ListMyOrgsResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListMyOrgsResponse{Organizations: []*authv1.Organization{{Id: "org-1", Name: "Acme"}}}, nil
}

func (s *orgSignupStub) ListMembers(ctx context.Context, in *authv1.ListMembersRequest) (*authv1.ListMembersResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListMembersResponse{Members: []*authv1.Membership{{OrgId: in.GetOrgId(), UserId: "user-1", Status: "active", Role: "owner"}}}, nil
}

func (s *orgSignupStub) SetOrgSlug(ctx context.Context, in *authv1.SetOrgSlugRequest) (*authv1.SetOrgSlugResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SetOrgSlugResponse{Organization: &authv1.Organization{Id: in.GetOrgId(), Name: "Acme", Slug: in.GetSlug()}}, nil
}

func (s *orgSignupStub) ResolveTenant(_ context.Context, in *authv1.ResolveTenantRequest) (*authv1.ResolveTenantResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.ResolveTenantResponse{OrgId: "org-1", Name: "Acme", Slug: "acme", Retired: in.GetSlug() != "acme"}, nil
}

func (s *orgSignupStub) AddMember(ctx context.Context, _ *authv1.AddMemberRequest) (*authv1.AddMemberResponse, error) {
	return &authv1.AddMemberResponse{}, s.record(ctx)
}

func (s *orgSignupStub) RemoveMember(ctx context.Context, _ *authv1.RemoveMemberRequest) (*authv1.RemoveMemberResponse, error) {
	return &authv1.RemoveMemberResponse{}, s.record(ctx)
}

func (s *orgSignupStub) SuspendMember(ctx context.Context, _ *authv1.SuspendMemberRequest) (*authv1.SuspendMemberResponse, error) {
	return &authv1.SuspendMemberResponse{}, s.record(ctx)
}

func (s *orgSignupStub) SetMemberRole(ctx context.Context, in *authv1.SetMemberRoleRequest) (*authv1.SetMemberRoleResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SetMemberRoleResponse{Membership: &authv1.Membership{OrgId: in.GetOrgId(), UserId: in.GetUserId(), Status: "active", Role: in.GetRole()}}, nil
}

func (s *orgSignupStub) InviteMember(ctx context.Context, in *authv1.InviteMemberRequest) (*authv1.InviteMemberResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	s.inviteReq = in
	invite := &authv1.Invite{Id: "invite-1", OrgId: in.GetOrgId(), Email: in.GetEmail(), Phone: in.GetPhone(), Role: in.GetRole()}
	if in.GetPhone() != "" {
		return &authv1.InviteMemberResponse{Invite: invite, Token: "raw-phone-token"}, nil
	}
	return &authv1.InviteMemberResponse{Invite: invite}, nil
}

func (s *orgSignupStub) GetInvitePreview(ctx context.Context, in *authv1.GetInvitePreviewRequest) (*authv1.InvitePreview, error) {
	s.previewToken = in.GetToken()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.InvitePreview{OrgId: "org-1", OrgName: "Acme", OrgSlug: "acme", Role: "admin", ExpiresAt: "2026-11-09T10:00:00Z"}, nil
}

func (s *orgSignupStub) AcceptInviteWithSignup(ctx context.Context, in *authv1.AcceptInviteWithSignupRequest) (*authv1.AcceptInviteWithSignupResponse, error) {
	s.signupReq = in
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.AcceptInviteWithSignupResponse{UserId: "user-9", OrgId: "org-1"}, nil
}

func (s *orgSignupStub) AcceptInvite(ctx context.Context, in *authv1.AcceptInviteRequest) (*authv1.AcceptInviteResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.AcceptInviteResponse{Invite: &authv1.Invite{Id: "invite-" + in.GetToken(), Status: "accepted"}}, nil
}

func (s *orgSignupStub) RevokeInvite(ctx context.Context, in *authv1.RevokeInviteRequest) (*authv1.RevokeInviteResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.RevokeInviteResponse{}, nil
}

func (s *orgSignupStub) ListInvites(ctx context.Context, in *authv1.ListInvitesRequest) (*authv1.ListInvitesResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListInvitesResponse{Invites: []*authv1.Invite{{Id: "invite-1", OrgId: in.GetOrgId()}}}, nil
}

func (s *orgSignupStub) SelectOrg(ctx context.Context, in *authv1.SelectOrgRequest) (*authv1.SelectOrgResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SelectOrgResponse{Tokens: &authv1.TokenResponse{AccessToken: "access-" + in.GetOrgId(), RefreshToken: "refresh", ExpiresAt: "e"}}, nil
}

func (s *orgSignupStub) RegisterWithEmail(ctx context.Context, _ *authv1.RegisterWithEmailRequest) (*authv1.RegisterWithEmailResponse, error) {
	return &authv1.RegisterWithEmailResponse{}, s.record(ctx)
}

func (s *orgSignupStub) VerifySignup(ctx context.Context, _ *authv1.VerifySignupRequest) (*authv1.VerifySignupResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.VerifySignupResponse{Tokens: &authv1.TokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: "e"}}, nil
}

func dialOrgStub(t *testing.T, err error) (*Client, *orgSignupStub) {
	t.Helper()
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	stub := &orgSignupStub{err: err}
	gs := grpc.NewServer()
	authv1.RegisterOrgServiceServer(gs, stub)
	authv1.RegisterTenantServiceServer(gs, stub)
	authv1.RegisterSignupServiceServer(gs, stub)
	authv1.RegisterInviteServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, dialErr := NewClient(listener.Addr().String())
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, stub
}

func TestOrgAndSignupCallsForwardTheBearerAndMapTheirTypes(t *testing.T) {
	client, stub := dialOrgStub(t, nil)
	ctx := context.Background()

	org, err := client.CreateOrg(ctx, "Acme", "", "token-1")
	if err != nil || org.ID != "org-Acme" || org.Name != "Acme" {
		t.Fatalf("CreateOrg = %+v, %v", org, err)
	}
	if stub.authorization != "Bearer token-1" {
		t.Fatalf("authorization = %q, want Bearer token-1", stub.authorization)
	}
	orgs, err := client.ListMyOrgs(ctx, "token-1")
	if err != nil || len(orgs) != 1 || orgs[0].Name != "Acme" {
		t.Fatalf("ListMyOrgs = %+v, %v", orgs, err)
	}
	members, err := client.ListMembers(ctx, "org-1", "token-1")
	if err != nil || len(members) != 1 || members[0].UserID != "user-1" {
		t.Fatalf("ListMembers = %+v, %v", members, err)
	}
	if err := client.AddMember(ctx, "org-1", "user-2", "token-1"); err != nil {
		t.Fatalf("AddMember = %v (a successful write must not be an error)", err)
	}
	if err := client.RemoveMember(ctx, "org-1", "user-2", "token-1"); err != nil {
		t.Fatalf("RemoveMember = %v", err)
	}
	if err := client.SuspendMember(ctx, "org-1", "user-2", "token-1"); err != nil {
		t.Fatalf("SuspendMember = %v", err)
	}
	changed, err := client.SetMemberRole(ctx, "org-1", "user-2", "admin", "token-1")
	if err != nil || changed.Role != "admin" || changed.UserID != "user-2" {
		t.Fatalf("SetMemberRole = %+v, %v", changed, err)
	}
	renamed, err := client.SetOrgSlug(ctx, "org-1", "new-name", "token-1")
	if err != nil || renamed.Slug != "new-name" {
		t.Fatalf("SetOrgSlug = %+v, %v", renamed, err)
	}
	tenant, err := client.ResolveTenant(ctx, "old-name")
	if err != nil || tenant.OrgID != "org-1" || tenant.Slug != "acme" || !tenant.Retired {
		t.Fatalf("ResolveTenant = %+v, %v", tenant, err)
	}
	created, err := client.InviteMember(ctx, domain.InviteRequest{OrgID: "org-1", Email: "person@example.com"}, "token-1")
	if err != nil || created.Invite.Email != "person@example.com" || created.Token != "" {
		t.Fatalf("InviteMember = %+v, %v", created, err)
	}
	accepted, err := client.AcceptInvite(ctx, "secret", "token-1")
	if err != nil || accepted.ID != "invite-secret" {
		t.Fatalf("AcceptInvite = %+v, %v", accepted, err)
	}
	if err := client.RevokeInvite(ctx, "org-1", "invite-1", "token-1"); err != nil {
		t.Fatalf("RevokeInvite = %v", err)
	}
	invites, err := client.ListInvites(ctx, "org-1", "token-1")
	if err != nil || len(invites) != 1 {
		t.Fatalf("ListInvites = %+v, %v", invites, err)
	}
	tokens, err := client.SelectOrg(ctx, "org-1", "refresh-old", "token-1")
	if err != nil || tokens.AccessToken != "access-org-1" {
		t.Fatalf("SelectOrg = %+v, %v", tokens, err)
	}

	if err := client.RegisterWithEmail(ctx, domain.SignupRegistration{Email: "person@example.com"}); err != nil {
		t.Fatalf("RegisterWithEmail = %v", err)
	}
	signupTokens, err := client.VerifySignup(ctx, domain.SignupVerification{Email: "person@example.com", Code: "123456"})
	if err != nil || signupTokens.AccessToken != "access" {
		t.Fatalf("VerifySignup = %+v, %v", signupTokens, err)
	}
}

func TestOrgStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want domain.Kind
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), domain.KindInvalidArgument},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad"), domain.KindUnauthenticated},
		{"not found", status.Error(codes.NotFound, "missing"), domain.KindNotFound},
		{"failed precondition", status.Error(codes.FailedPrecondition, "last owner"), domain.KindConflict},
		{"already exists", status.Error(codes.AlreadyExists, "organization slug is taken"), domain.KindConflict},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "slow down"), domain.KindResourceExhausted},
		{"permission denied is forbidden", status.Error(codes.PermissionDenied, "no"), domain.KindPermissionDenied},
		{"internal hides the detail", status.Error(codes.Internal, "pg: reset"), domain.KindBadGateway},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialOrgStub(t, tc.err)
			_, err := client.ListMyOrgs(context.Background(), "token-1")
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.want {
				t.Fatalf("err = %v, want kind %v", err, tc.want)
			}
			if tc.want == domain.KindBadGateway && failure.Message != "upstream error" {
				t.Fatalf("message = %q, want the generic upstream error", failure.Message)
			}
		})
	}
}

func TestSignupFailedPreconditionBecomesNotFound(t *testing.T) {
	client, _ := dialOrgStub(t, status.Error(codes.FailedPrecondition, "sign-up is disabled"))

	err := client.RegisterWithEmail(context.Background(), domain.SignupRegistration{Email: "person@example.com"})
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindNotFound {
		t.Fatalf("RegisterWithEmail err = %v, want KindNotFound", err)
	}

	_, err = client.VerifySignup(context.Background(), domain.SignupVerification{Email: "person@example.com"})
	failure, ok = domain.AsError(err)
	if !ok || failure.Kind != domain.KindNotFound {
		t.Fatalf("VerifySignup err = %v, want KindNotFound", err)
	}
}

func TestResolveTenantMapsNotFoundAndHidesOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want domain.Kind
	}{
		{"not found", status.Error(codes.NotFound, "tenant not found"), domain.KindNotFound},
		{"internal", status.Error(codes.Internal, "pg: connection reset"), domain.KindBadGateway},
		{"permission denied", status.Error(codes.PermissionDenied, "detail"), domain.KindBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialOrgStub(t, tc.err)
			_, err := client.ResolveTenant(context.Background(), "acme")
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.want {
				t.Fatalf("err = %v, want kind %v", err, tc.want)
			}
			if tc.want == domain.KindBadGateway && failure.Message != "upstream error" {
				t.Fatalf("message = %q, want the generic upstream error", failure.Message)
			}
		})
	}
}
