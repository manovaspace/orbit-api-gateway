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
		CreatedAt: "2026-11-02T10:00:00Z",
		UpdatedAt: "2026-11-02T10:00:00Z",
	}}}, nil
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
			wantBody:   `{"organizations":[{"id":"org-1","name":"Acme","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}]}` + "\n",
		},
		{
			name: "create org", method: http.MethodPost, path: routeOrgCreate, body: `{"name":"Created"}`,
			wantStatus: http.StatusOK,
			wantBody:   `{"organization":{"id":"org-created","name":"Created","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}}` + "\n",
		},
		{
			name: "list members", method: http.MethodGet, path: "/api/v1/orgs/org-1/members",
			wantStatus: http.StatusOK,
			wantBody:   `{"members":[{"org_id":"org-1","user_id":"user-1","status":"active","created_at":"2026-11-02T10:00:00Z","updated_at":"2026-11-02T10:00:00Z"}]}` + "\n",
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
		{"permission denied is a gateway failure", status.Error(codes.PermissionDenied, "secret detail"), http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
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

	t.Run("org route is per organization", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &orgSignupStub{}
		base := newOrgSignupEnv(t, stub, limiter)

		got := send(t, base, http.MethodGet, "/api/v1/orgs/org-1/members", "", bearer())
		if got.Status != http.StatusOK {
			t.Fatalf("status = %d", got.Status)
		}
		want := ratelimit.KeyForOrg("org-1", routeOrgMembers)
		if len(limiter.keys) != 1 || limiter.keys[0] != want {
			t.Fatalf("limiter keys = %v, want %q", limiter.keys, want)
		}
		if limiter.policies[0] != domain.OrgRoutePolicy(routeOrgMembers) {
			t.Fatalf("policy = %+v", limiter.policies[0])
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
		want := ratelimit.KeyForOrg("org-9", routeSessionOrg)
		if len(limiter.keys) != 1 || limiter.keys[0] != want {
			t.Fatalf("limiter keys = %v, want %q", limiter.keys, want)
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
