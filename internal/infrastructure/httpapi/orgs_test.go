package httpapi

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

const testAccessToken = "access-token"

// orgSignupStub is the in-process orbit-auth stand-in. It answers success
// unless err is set, and records what the adapter forwarded.
type orgSignupStub struct {
	authv1.UnimplementedOrgServiceServer
	authv1.UnimplementedTenantServiceServer
	authv1.UnimplementedSignupServiceServer

	mu  sync.Mutex
	err error

	authorization string
	orgCalls      int
	signupCalls   int
	orgID         string
	inviteID      string
	email         string
	inviteToken   string
	name          string
	refreshToken  string
	role          string
	slug          string
	tenantCalls   int
}

func (s *orgSignupStub) record(ctx context.Context) error {
	s.mu.Lock()
	s.orgCalls++
	s.authorization = firstMetadata(ctx, "authorization")
	err := s.err
	s.mu.Unlock()
	return err
}

func (s *orgSignupStub) recordSignup(ctx context.Context) error {
	s.mu.Lock()
	s.signupCalls++
	s.authorization = firstMetadata(ctx, "authorization")
	err := s.err
	s.mu.Unlock()
	return err
}

func firstMetadata(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func (s *orgSignupStub) CreateOrg(ctx context.Context, in *authv1.CreateOrgRequest) (*authv1.CreateOrgResponse, error) {
	s.mu.Lock()
	s.name = in.GetName()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.CreateOrgResponse{Organization: &authv1.Organization{
		Id:        "org-created",
		Name:      in.GetName(),
		Slug:      "created-slug",
		CreatedAt: "2026-11-02T10:00:00Z",
		UpdatedAt: "2026-11-02T10:00:00Z",
	}}, nil
}

func (s *orgSignupStub) ListMyOrgs(ctx context.Context, _ *authv1.ListMyOrgsRequest) (*authv1.ListMyOrgsResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListMyOrgsResponse{Organizations: []*authv1.Organization{{
		Id:        "org-1",
		Name:      "Acme",
		Slug:      "acme",
		CreatedAt: "2026-11-02T10:00:00Z",
		UpdatedAt: "2026-11-02T10:00:00Z",
	}}}, nil
}

func (s *orgSignupStub) ListMembers(ctx context.Context, in *authv1.ListMembersRequest) (*authv1.ListMembersResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListMembersResponse{Members: []*authv1.Membership{{
		OrgId:     in.GetOrgId(),
		UserId:    "user-1",
		Status:    "active",
		Role:      "owner",
		CreatedAt: "2026-11-02T10:00:00Z",
		UpdatedAt: "2026-11-02T10:00:00Z",
	}}}, nil
}

func (s *orgSignupStub) SetOrgSlug(ctx context.Context, in *authv1.SetOrgSlugRequest) (*authv1.SetOrgSlugResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.slug = in.GetSlug()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SetOrgSlugResponse{Organization: &authv1.Organization{
		Id: in.GetOrgId(), Name: "Acme", Slug: in.GetSlug(),
		CreatedAt: "2026-11-02T10:00:00Z", UpdatedAt: "2026-11-02T10:00:00Z",
	}}, nil
}

// ResolveTenant is the unauthenticated lookup: it records no bearer token and
// does not count as an organization call.
func (s *orgSignupStub) ResolveTenant(ctx context.Context, in *authv1.ResolveTenantRequest) (*authv1.ResolveTenantResponse, error) {
	s.mu.Lock()
	s.slug = in.GetSlug()
	s.tenantCalls++
	s.authorization = firstMetadata(ctx, "authorization")
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if in.GetSlug() == "unknown" {
		return nil, status.Error(codes.NotFound, "tenant not found")
	}
	return &authv1.ResolveTenantResponse{OrgId: "org-1", Name: "Acme", Slug: "acme", Retired: in.GetSlug() != "acme"}, nil
}

func (s *orgSignupStub) AddMember(ctx context.Context, in *authv1.AddMemberRequest) (*authv1.AddMemberResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.AddMemberResponse{}, nil
}

func (s *orgSignupStub) RemoveMember(ctx context.Context, in *authv1.RemoveMemberRequest) (*authv1.RemoveMemberResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.RemoveMemberResponse{}, nil
}

func (s *orgSignupStub) SuspendMember(ctx context.Context, in *authv1.SuspendMemberRequest) (*authv1.SuspendMemberResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SuspendMemberResponse{}, nil
}

func (s *orgSignupStub) SetMemberRole(ctx context.Context, in *authv1.SetMemberRoleRequest) (*authv1.SetMemberRoleResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.role = in.GetRole()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SetMemberRoleResponse{Membership: &authv1.Membership{
		OrgId:     in.GetOrgId(),
		UserId:    in.GetUserId(),
		Status:    "active",
		Role:      in.GetRole(),
		CreatedAt: "2026-11-02T10:00:00Z",
		UpdatedAt: "2026-11-02T10:00:00Z",
	}}, nil
}

func (s *orgSignupStub) InviteMember(ctx context.Context, in *authv1.InviteMemberRequest) (*authv1.InviteMemberResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.email = in.GetEmail()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.InviteMemberResponse{Invite: pendingInvite(in.GetOrgId(), in.GetEmail())}, nil
}

func (s *orgSignupStub) AcceptInvite(ctx context.Context, in *authv1.AcceptInviteRequest) (*authv1.AcceptInviteResponse, error) {
	s.mu.Lock()
	s.inviteToken = in.GetToken()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.AcceptInviteResponse{Invite: &authv1.Invite{
		Id:         "invite-1",
		OrgId:      "org-1",
		Email:      "person@example.com",
		InviterId:  "user-1",
		Status:     "accepted",
		ExpiresAt:  "2026-11-09T10:00:00Z",
		AcceptedAt: "2026-11-02T10:00:00Z",
		CreatedAt:  "2026-11-02T10:00:00Z",
	}}, nil
}

func (s *orgSignupStub) RevokeInvite(ctx context.Context, in *authv1.RevokeInviteRequest) (*authv1.RevokeInviteResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.inviteID = in.GetInviteId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.RevokeInviteResponse{}, nil
}

func (s *orgSignupStub) ListInvites(ctx context.Context, in *authv1.ListInvitesRequest) (*authv1.ListInvitesResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.ListInvitesResponse{Invites: []*authv1.Invite{
		pendingInvite(in.GetOrgId(), "pending@example.com"),
	}}, nil
}

func (s *orgSignupStub) SelectOrg(ctx context.Context, in *authv1.SelectOrgRequest) (*authv1.SelectOrgResponse, error) {
	s.mu.Lock()
	s.orgID = in.GetOrgId()
	s.refreshToken = in.GetRefreshToken()
	s.mu.Unlock()
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	return &authv1.SelectOrgResponse{Tokens: &authv1.TokenResponse{
		AccessToken:  "access-org",
		RefreshToken: "refresh-org",
		ExpiresAt:    "2026-11-02T11:00:00Z",
	}}, nil
}

func (s *orgSignupStub) RegisterWithEmail(ctx context.Context, _ *authv1.RegisterWithEmailRequest) (*authv1.RegisterWithEmailResponse, error) {
	if err := s.recordSignup(ctx); err != nil {
		return nil, err
	}
	return &authv1.RegisterWithEmailResponse{}, nil
}

func (s *orgSignupStub) VerifySignup(ctx context.Context, _ *authv1.VerifySignupRequest) (*authv1.VerifySignupResponse, error) {
	if err := s.recordSignup(ctx); err != nil {
		return nil, err
	}
	return &authv1.VerifySignupResponse{Tokens: &authv1.TokenResponse{
		AccessToken:  "access-signup",
		RefreshToken: "refresh-signup",
		ExpiresAt:    "2026-11-02T11:00:00Z",
	}}, nil
}

func pendingInvite(orgID, email string) *authv1.Invite {
	return &authv1.Invite{
		Id:        "invite-1",
		OrgId:     orgID,
		Email:     email,
		InviterId: "user-1",
		Status:    "pending",
		ExpiresAt: "2026-11-09T10:00:00Z",
		CreatedAt: "2026-11-02T10:00:00Z",
	}
}

func (s *orgSignupStub) seen() (authorization string, orgCalls, signupCalls int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorization, s.orgCalls, s.signupCalls
}

// newOrgSignupEnv starts the real HTTP edge over an in-process gRPC orbit-auth
// stand-in. It wires only the org and signup ports.
func newOrgSignupEnv(t *testing.T, stub *orgSignupStub, limiter domain.Limiter) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv1.RegisterOrgServiceServer(gs, stub)
	authv1.RegisterTenantServiceServer(gs, stub)
	authv1.RegisterSignupServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := authclient.NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	svc := application.NewService(application.Deps{
		Orgs:    client,
		Tenants: client,
		Signup:  client,
		Limiter: limiter,
		Assets:  assets.New("openapi"),
	})
	return serveOnLoopback(t, New(svc, Options{JWTSecret: "test-secret"}))
}

func bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testAccessToken}
}

func TestSignupReturnsTheSameAcceptedBodyForNewAndExistingAddresses(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)

	first := send(t, base, http.MethodPost, routeSignup,
		`{"email":"new@example.com","password":"correct horse","display_name":"New","locale":"en","org_name":"Acme","invite_token":""}`, nil)
	second := send(t, base, http.MethodPost, routeSignup,
		`{"email":"existing@example.com","password":"correct horse","display_name":"Existing","locale":"fa"}`, nil)

	if first.Status != http.StatusAccepted || first.Body != `{"status":"verification_sent"}`+"\n" {
		t.Fatalf("new address = %d %q", first.Status, first.Body)
	}
	if second.Status != http.StatusAccepted || second.Body != first.Body {
		t.Fatalf("existing address = %d %q, want the same body %q", second.Status, second.Body, first.Body)
	}
	if first.ContentType != "application/json" {
		t.Fatalf("content-type = %q", first.ContentType)
	}
	if _, _, signupCalls := stub.seen(); signupCalls != 2 {
		t.Fatalf("signup calls = %d, want 2", signupCalls)
	}
}

func TestSignupVerifyReturnsTokenPair(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeSignupVerify,
		`{"email":"new@example.com","code":"123456","password":"correct horse"}`, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	want := `{"access_token":"access-signup","expires_at":"2026-11-02T11:00:00Z","refresh_token":"refresh-signup"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}
}

func TestOrgRoutesForwardTheBearerTokenAndReturnTheirShapes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			name: "list my orgs", method: http.MethodGet, path: routeOrgList,
			wantStatus: http.StatusOK,
			wantBody:   `{"organizations":[{"id":"org-1","name":"Acme","slug":"acme","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}]}` + "\n",
		},
		{
			name: "create org", method: http.MethodPost, path: routeOrgCreate, body: `{"name":"Created"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"organization":{"id":"org-created","name":"Created","slug":"created-slug","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "list members", method: http.MethodGet, path: "/api/v1/orgs/org-1/members",
			wantStatus: http.StatusOK,
			wantBody:   `{"members":[{"org_id":"org-1","user_id":"user-1","status":"active","role":"owner","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}]}` + "\n",
		},
		{
			name: "add member", method: http.MethodPost, path: "/api/v1/orgs/org-1/members", body: `{"user_id":"user-2"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"status":"added"}` + "\n",
		},
		{
			name: "remove member", method: http.MethodDelete, path: "/api/v1/orgs/org-1/members/user-2",
			wantStatus: http.StatusOK,
			wantBody:   `{"status":"removed"}` + "\n",
		},
		{
			name: "suspend member", method: http.MethodPost, path: "/api/v1/orgs/org-1/members/user-2/suspend",
			wantStatus: http.StatusOK,
			wantBody:   `{"status":"suspended"}` + "\n",
		},
		{
			name: "set org slug", method: http.MethodPut, path: "/api/v1/orgs/org-1/slug", body: `{"slug":" new-name "}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"organization":{"id":"org-1","name":"Acme","slug":"new-name","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "set member role", method: http.MethodPut, path: "/api/v1/orgs/org-1/members/user-2/role", body: `{"role":" admin "}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"membership":{"org_id":"org-1","user_id":"user-2","status":"active","role":"admin","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "create invite", method: http.MethodPost, path: "/api/v1/orgs/org-1/invites", body: `{"email":"person@example.com"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"invite":{"id":"invite-1","org_id":"org-1","email":"person@example.com","inviter_id":"user-1","status":"pending","expires_at":"2026-11-09T10:00:00Z","created_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "list invites", method: http.MethodGet, path: "/api/v1/orgs/org-1/invites",
			wantStatus: http.StatusOK,
			wantBody:   `{"invites":[{"id":"invite-1","org_id":"org-1","email":"pending@example.com","inviter_id":"user-1","status":"pending","expires_at":"2026-11-09T10:00:00Z","created_at":"2026-11-02T10:00:00Z"}]}` + "\n",
		},
		{
			name: "revoke invite", method: http.MethodDelete, path: "/api/v1/orgs/org-1/invites/invite-1",
			wantStatus: http.StatusOK,
			wantBody:   `{"status":"revoked"}` + "\n",
		},
		{
			name: "accept invite", method: http.MethodPost, path: routeInviteAccept, body: `{"token":"invite-secret"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"invite":{"id":"invite-1","org_id":"org-1","email":"person@example.com","inviter_id":"user-1","status":"accepted","expires_at":"2026-11-09T10:00:00Z","accepted_at":"2026-11-02T10:00:00Z","created_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "select org", method: http.MethodPost, path: routeSessionOrg, body: `{"org_id":"org-1","refresh_token":"refresh-old"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"access_token":"access-org","expires_at":"2026-11-02T11:00:00Z","refresh_token":"refresh-org"}` + "\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &orgSignupStub{}
			base := newOrgSignupEnv(t, stub, nil)

			headers := bearer()
			if tc.body != "" {
				headers["Content-Type"] = "application/json"
			}
			got := send(t, base, tc.method, tc.path, tc.body, headers)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", got.Status, tc.wantStatus, got.Body)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q\nwant   %q", got.Body, tc.wantBody)
			}
			authorization, _, _ := stub.seen()
			if authorization != "Bearer "+testAccessToken {
				t.Fatalf("upstream authorization = %q, want the caller's bearer token", authorization)
			}
		})
	}
}

func TestOrgRoutesRequireABearerToken(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"list orgs", http.MethodGet, routeOrgList, ""},
		{"create org", http.MethodPost, routeOrgCreate, `{"name":"Acme"}`},
		{"list members", http.MethodGet, "/api/v1/orgs/org-1/members", ""},
		{"add member", http.MethodPost, "/api/v1/orgs/org-1/members", `{"user_id":"user-2"}`},
		{"remove member", http.MethodDelete, "/api/v1/orgs/org-1/members/user-2", ""},
		{"suspend member", http.MethodPost, "/api/v1/orgs/org-1/members/user-2/suspend", ""},
		{"set member role", http.MethodPut, "/api/v1/orgs/org-1/members/user-2/role", `{"role":"admin"}`},
		{"set org slug", http.MethodPut, "/api/v1/orgs/org-1/slug", `{"slug":"new-name"}`},
		{"create invite", http.MethodPost, "/api/v1/orgs/org-1/invites", `{"email":"p@example.com"}`},
		{"list invites", http.MethodGet, "/api/v1/orgs/org-1/invites", ""},
		{"revoke invite", http.MethodDelete, "/api/v1/orgs/org-1/invites/invite-1", ""},
		{"accept invite", http.MethodPost, routeInviteAccept, `{"token":"t"}`},
		{"select org", http.MethodPost, routeSessionOrg, `{"org_id":"org-1","refresh_token":"r"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := send(t, base, tc.method, tc.path, tc.body, nil)
			if got.Status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", got.Status)
			}
			if got.Body != `{"error":"missing bearer token"}`+"\n" {
				t.Fatalf("body = %q", got.Body)
			}
		})
	}
	if _, orgCalls, _ := stub.seen(); orgCalls != 0 {
		t.Fatalf("upstream calls = %d, want none", orgCalls)
	}
}

func TestOrgStatusMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "bad request"), http.StatusBadRequest, `{"error":"bad request"}` + "\n"},
		{"unauthenticated", status.Error(codes.Unauthenticated, "authentication required"), http.StatusUnauthorized, `{"error":"authentication required"}` + "\n"},
		{"not found", status.Error(codes.NotFound, "organization not found"), http.StatusNotFound, `{"error":"organization not found"}` + "\n"},
		{"failed precondition", status.Error(codes.FailedPrecondition, "last owner"), http.StatusConflict, `{"error":"last owner"}` + "\n"},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "slow down"), http.StatusTooManyRequests, `{"error":"slow down"}` + "\n"},
		{"permission denied is forbidden", status.Error(codes.PermissionDenied, "organization administration required"), http.StatusForbidden, `{"error":"organization administration required"}` + "\n"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: connection reset"), http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
		{"plain error", context.DeadlineExceeded, http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &orgSignupStub{err: tc.err}
			base := newOrgSignupEnv(t, stub, nil)

			got := send(t, base, http.MethodGet, routeOrgList, "", bearer())
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
		})
	}
}

func TestSignupStatusMappingAndDisabledSurface(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "invalid email"), http.StatusBadRequest, `{"error":"invalid email"}` + "\n"},
		{"disabled signup is a 404", status.Error(codes.FailedPrecondition, "sign-up is disabled"), http.StatusNotFound, `{"error":"not found"}` + "\n"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: connection reset"), http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &orgSignupStub{err: tc.err}
			base := newOrgSignupEnv(t, stub, nil)

			got := send(t, base, http.MethodPost, routeSignup,
				`{"email":"new@example.com","password":"p"}`, nil)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if got.Body != tc.wantBody {
				t.Fatalf("body = %q, want %q", got.Body, tc.wantBody)
			}
		})
	}
}

func TestSignupVerifyDisabledSurfaceIsA404(t *testing.T) {
	stub := &orgSignupStub{err: status.Error(codes.FailedPrecondition, "sign-up is disabled")}
	base := newOrgSignupEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeSignupVerify,
		`{"email":"new@example.com","code":"123456","password":"p"}`, nil)
	if got.Status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", got.Status)
	}
}

func TestRouteRateLimitsUseIPAndOrgBuckets(t *testing.T) {
	t.Run("signup is per IP", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodPost, routeSignup,
			`{"email":"new@example.com","password":"p"}`, nil)
		if got.Status != http.StatusAccepted {
			t.Fatalf("status = %d", got.Status)
		}
		want := ratelimit.KeyForIP("127.0.0.1", routeSignup)
		if len(limiter.keys) != 1 || limiter.keys[0] != want {
			t.Fatalf("limiter keys = %v, want %q", limiter.keys, want)
		}
		if limiter.policies[0] != domain.IPRoutePolicy(routeSignup, domain.SignupIPLimit) {
			t.Fatalf("policy = %+v", limiter.policies[0])
		}
	})

	t.Run("invite accept is per IP", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodPost, routeInviteAccept, `{"token":"invite-secret"}`, bearer())
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d", got.Status)
		}
		want := ratelimit.KeyForIP("127.0.0.1", routeInviteAccept)
		if len(limiter.keys) != 1 || limiter.keys[0] != want {
			t.Fatalf("limiter keys = %v, want %q", limiter.keys, want)
		}
		if limiter.policies[0] != domain.IPRoutePolicy(routeInviteAccept, domain.InviteAcceptIPLimit) {
			t.Fatalf("policy = %+v", limiter.policies[0])
		}
	})

	t.Run("org route is per IP then per caller and organization", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", bearer())
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d", got.Status)
		}
		wantIP := ratelimit.KeyForIP("127.0.0.1", routeOrgMembers)
		wantOrg := orgCallerKey("org-1", testAccessToken, routeOrgMembers)
		if len(limiter.keys) != 2 || limiter.keys[0] != wantIP || limiter.keys[1] != wantOrg {
			t.Fatalf("limiter keys = %v, want [%q %q]", limiter.keys, wantIP, wantOrg)
		}
		if limiter.policies[0] != domain.IPRoutePolicy(routeOrgMembers, domain.OrgRouteIPLimit) {
			t.Fatalf("ip policy = %+v", limiter.policies[0])
		}
		if limiter.policies[1] != domain.OrgRoutePolicy(routeOrgMembers) {
			t.Fatalf("org policy = %+v", limiter.policies[1])
		}
	})

	t.Run("unauthenticated org request does not touch the org bucket", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", nil)
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got.Status)
		}
		want := ratelimit.KeyForIP("127.0.0.1", routeOrgMembers)
		if len(limiter.keys) != 1 || limiter.keys[0] != want {
			t.Fatalf("limiter keys = %v, want only %q", limiter.keys, want)
		}
	})

	t.Run("two callers get separate org buckets", func(t *testing.T) {
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, ratelimit.New(ratelimiting.NewMemoryLimiter()))
		attacker := map[string]string{"Authorization": "Bearer attacker-token"}

		for i := 0; i < domain.OrgRouteLimit; i++ {
			got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", attacker)
			if got.Status != http.StatusOK {
				t.Fatalf("attacker request %d status = %d, want 200", i+1, got.Status)
			}
		}
		got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", attacker)
		if got.Status != http.StatusTooManyRequests {
			t.Fatalf("attacker status = %d, want 429", got.Status)
		}
		got = send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", bearer())
		if got.Status != http.StatusOK {
			t.Fatalf("legitimate caller status = %d, want 200", got.Status)
		}
	})

	t.Run("org denial is a 429", func(t *testing.T) {
		limiter := &recordingLimiter{}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", bearer())
		if got.Status != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", got.Status)
		}
		if got.Body != `{"error":"rate limit exceeded"}`+"\n" {
			t.Fatalf("body = %q", got.Body)
		}
		if got.RetryAfter == "" {
			t.Fatal("retry-after is missing")
		}
	})

	t.Run("session select org uses the body organization", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodPost, routeSessionOrg,
			`{"org_id":"org-9","refresh_token":"refresh-old"}`, bearer())
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d", got.Status)
		}
		wantIP := ratelimit.KeyForIP("127.0.0.1", routeSessionOrg)
		want := orgCallerKey("org-9", testAccessToken, routeSessionOrg)
		if len(limiter.keys) != 2 || limiter.keys[0] != wantIP || limiter.keys[1] != want {
			t.Fatalf("limiter keys = %v, want [%q %q]", limiter.keys, wantIP, want)
		}
		if limiter.policies[0] != domain.IPRoutePolicy(routeSessionOrg, domain.OrgRouteIPLimit) {
			t.Fatalf("ip policy = %+v", limiter.policies[0])
		}
	})
}

func TestSignupRateLimitReturns429(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, ratelimit.New(ratelimiting.NewMemoryLimiter()))

	for i := 0; i < domain.SignupIPLimit; i++ {
		got := send(t, base, http.MethodPost, routeSignup,
			`{"email":"new@example.com","password":"p"}`, nil)
		if got.Status != http.StatusAccepted {
			t.Fatalf("request %d status = %d, want 202", i+1, got.Status)
		}
	}
	got := send(t, base, http.MethodPost, routeSignup,
		`{"email":"new@example.com","password":"p"}`, nil)
	if got.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got.Status)
	}
	if got.Body != `{"error":"rate limit exceeded"}`+"\n" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.RetryAfter == "" {
		t.Fatal("retry-after is missing")
	}
}

func TestSignupBodyCap(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)

	body := `{"email":"` + strings.Repeat("a", maxAuthBody) + `"}`
	got := send(t, base, http.MethodPost, routeSignup, body, nil)
	if got.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", got.Status)
	}
	if got.Body != `{"error":"invalid json"}`+"\n" {
		t.Fatalf("body = %q", got.Body)
	}
	if _, _, signupCalls := stub.seen(); signupCalls != 0 {
		t.Fatalf("upstream signup calls = %d, want none", signupCalls)
	}
}

// recordingLimiter records the key and policy without any storage.
type recordingLimiter struct {
	allow    bool
	keys     []string
	policies []domain.Policy
}

func (l *recordingLimiter) Allow(_ context.Context, key string, policy domain.Policy) (domain.Decision, error) {
	l.keys = append(l.keys, key)
	l.policies = append(l.policies, policy)
	if !l.allow {
		return domain.Decision{Allowed: false, Limit: policy.Limit, RetryAfter: time.Second}, nil
	}
	return domain.Decision{Allowed: true, Limit: policy.Limit, Remaining: policy.Limit - 1}, nil
}

// TestMembershipWritesSurfaceOrbitAuthAuthorization proves a member without
// organization administration authority gets 403 on every membership and
// invitation write, and a last-owner refusal is a 409, whatever the route.
func TestMembershipWritesSurfaceOrbitAuthAuthorization(t *testing.T) {
	routes := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"add member", http.MethodPost, "/api/v1/orgs/org-1/members", `{"user_id":"user-2"}`},
		{"remove member", http.MethodDelete, "/api/v1/orgs/org-1/members/user-2", ""},
		{"suspend member", http.MethodPost, "/api/v1/orgs/org-1/members/user-2/suspend", ""},
		{"set member role", http.MethodPut, "/api/v1/orgs/org-1/members/user-2/role", `{"role":"admin"}`},
		{"create invite", http.MethodPost, "/api/v1/orgs/org-1/invites", `{"email":"p@example.com"}`},
		{"list invites", http.MethodGet, "/api/v1/orgs/org-1/invites", ""},
		{"revoke invite", http.MethodDelete, "/api/v1/orgs/org-1/invites/invite-1", ""},
	}
	for _, route := range routes {
		t.Run(route.name+" forbidden", func(t *testing.T) {
			base := newOrgSignupEnv(t, &orgSignupStub{err: status.Error(codes.PermissionDenied, "organization administration required")}, nil)
			headers := bearer()
			if route.body != "" {
				headers["Content-Type"] = "application/json"
			}
			got := send(t, base, route.method, route.path, route.body, headers)
			if got.Status != http.StatusForbidden || got.Body != `{"error":"organization administration required"}`+"\n" {
				t.Fatalf("got %d %q, want 403 with the orbit-auth message", got.Status, got.Body)
			}
		})
		t.Run(route.name+" last owner", func(t *testing.T) {
			base := newOrgSignupEnv(t, &orgSignupStub{err: status.Error(codes.FailedPrecondition, "organization must keep at least one active owner")}, nil)
			headers := bearer()
			if route.body != "" {
				headers["Content-Type"] = "application/json"
			}
			got := send(t, base, route.method, route.path, route.body, headers)
			if got.Status != http.StatusConflict {
				t.Fatalf("status = %d, want 409", got.Status)
			}
		})
	}
}

func TestSetMemberRoleForwardsTheTrimmedRole(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)
	headers := bearer()
	headers["Content-Type"] = "application/json"

	got := send(t, base, http.MethodPut, "/api/v1/orgs/org-1/members/user-2/role", `{"role":" owner "}`, headers)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.role != "owner" || stub.orgID != "org-1" {
		t.Fatalf("forwarded role %q org %q, want owner org-1", stub.role, stub.orgID)
	}
}

func TestOrgSlugWriteSurfacesOrbitAuthAnswers(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"not an owner", status.Error(codes.PermissionDenied, "organization administration required"), http.StatusForbidden},
		{"slug taken", status.Error(codes.AlreadyExists, "organization slug is taken"), http.StatusConflict},
		{"invalid slug", status.Error(codes.InvalidArgument, "invalid organization slug"), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newOrgSignupEnv(t, &orgSignupStub{err: tc.err}, nil)
			headers := bearer()
			headers["Content-Type"] = "application/json"
			got := send(t, base, http.MethodPut, "/api/v1/orgs/org-1/slug", `{"slug":"x"}`, headers)
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", got.Status, tc.wantStatus, got.Body)
			}
		})
	}
}

func TestCreateOrgForwardsTheOptionalSlug(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)
	headers := bearer()
	headers["Content-Type"] = "application/json"
	if got := send(t, base, http.MethodPost, routeOrgCreate, `{"name":"Created","slug":" Created-Slug "}`, headers); got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
}

// TestTenantResolveIsPublicAndReturnsOnlyThePublicFields proves the lookup the
// web edge makes before sign-in needs no token, forwards none, and answers only
// the organization id, name and current slug.
func TestTenantResolveIsPublicAndReturnsOnlyThePublicFields(t *testing.T) {
	stub := &orgSignupStub{}
	base := newOrgSignupEnv(t, stub, nil)

	got := send(t, base, http.MethodGet, "/api/v1/public/tenants/acme", "", nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
	if want := `{"org_id":"org-1","slug":"acme","name":"Acme","retired":false}` + "\n"; got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	if got.CacheControl != "public, max-age=30" {
		t.Fatalf("cache-control = %q, want a short public cache", got.CacheControl)
	}

	retired := send(t, base, http.MethodGet, "/api/v1/public/tenants/old-name", "", nil)
	if retired.Status != http.StatusOK || !strings.Contains(retired.Body, `"retired":true`) || !strings.Contains(retired.Body, `"slug":"acme"`) {
		t.Fatalf("retired = %d %q, want the current slug and retired true", retired.Status, retired.Body)
	}

	unknown := send(t, base, http.MethodGet, "/api/v1/public/tenants/unknown", "", nil)
	if unknown.Status != http.StatusNotFound || unknown.Body != `{"error":"tenant not found"}`+"\n" {
		t.Fatalf("unknown = %d %q, want 404 tenant not found", unknown.Status, unknown.Body)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.authorization != "" {
		t.Fatalf("the public lookup forwarded %q to Orbit Auth", stub.authorization)
	}
	if stub.orgCalls != 0 || stub.tenantCalls != 3 {
		t.Fatalf("orgCalls = %d, tenantCalls = %d; want 0 and 3", stub.orgCalls, stub.tenantCalls)
	}
}

func TestTenantResolveHidesUpstreamFailures(t *testing.T) {
	base := newOrgSignupEnv(t, &orgSignupStub{err: status.Error(codes.Internal, "pg: connection reset")}, nil)
	got := send(t, base, http.MethodGet, "/api/v1/public/tenants/acme", "", nil)
	if got.Status != http.StatusBadGateway || got.Body != `{"error":"upstream error"}`+"\n" {
		t.Fatalf("got %d %q, want the generic 502", got.Status, got.Body)
	}
}
