package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	ratelimiting "github.com/manovaspace/orbit-kit/ratelimiting"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/staffoidc"
)

const (
	suUserID = "3f0c6a4e-1b7d-4c2e-9a8f-5d6e7f8a9b0c"
	suReason = "account review 77"
	suEmail  = "ada@example.com"
)

// suStub is the in-process orbit-auth StaffUserService. It records the metadata
// of the last call and of the last write, and keeps the account status a write
// changes so a read after it sees the new state.
type suStub struct {
	authv1.UnimplementedStaffUserServiceServer

	mu       sync.Mutex
	err      error
	calls    int
	md       metadata.MD
	writeMD  metadata.MD
	list     *authv1.ListUsersRequest
	getID    string
	audit    *authv1.ListAuditEventsRequest
	disabled bool
	writes   []string
}

func (s *suStub) record(ctx context.Context, write bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	md, _ := metadata.FromIncomingContext(ctx)
	s.md = md
	if write {
		s.writeMD = md
	}
	return s.err
}

func (s *suStub) meta(md metadata.MD, key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := md.Get(key)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (s *suStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *suStub) statusValue() string {
	if s.disabled {
		return "disabled"
	}
	return "active"
}

func (s *suStub) user(id string) *authv1.StaffUser {
	return &authv1.StaffUser{
		Id:              id,
		Email:           suEmail,
		Username:        "ada",
		DisplayName:     "Ada",
		Status:          s.statusValue(),
		EmailVerified:   true,
		HasPassword:     true,
		CreatedAt:       "2026-11-01T10:00:00Z",
		MembershipCount: 1,
	}
}

func (s *suStub) ListUsers(ctx context.Context, in *authv1.ListUsersRequest) (*authv1.ListUsersResponse, error) {
	if err := s.record(ctx, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.list = in
	s.mu.Unlock()
	return &authv1.ListUsersResponse{Users: []*authv1.StaffUser{s.user(suUserID)}, NextPageToken: "next-1"}, nil
}

func (s *suStub) GetUser(ctx context.Context, in *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if err := s.record(ctx, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.getID = in.GetUserId()
	s.mu.Unlock()
	return &authv1.GetUserResponse{
		User: s.user(in.GetUserId()),
		Memberships: []*authv1.StaffUserMembership{{
			OrgId: srOrgID, OrgName: "Acme", OrgSlug: "acme", OrgStatus: "active",
			Role: "owner", Status: "active", JoinedAt: "2026-11-01T10:00:00Z",
		}},
	}, nil
}

func (s *suStub) DisableUser(ctx context.Context, in *authv1.DisableUserRequest) (*authv1.DisableUserResponse, error) {
	if err := s.record(ctx, true); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !s.disabled
	s.disabled = true
	s.writes = append(s.writes, "disable "+in.GetUserId())
	return &authv1.DisableUserResponse{Changed: changed}, nil
}

func (s *suStub) EnableUser(ctx context.Context, in *authv1.EnableUserRequest) (*authv1.EnableUserResponse, error) {
	if err := s.record(ctx, true); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := s.disabled
	s.disabled = false
	s.writes = append(s.writes, "enable "+in.GetUserId())
	return &authv1.EnableUserResponse{Changed: changed}, nil
}

func (s *suStub) ListAuditEvents(ctx context.Context, in *authv1.ListAuditEventsRequest) (*authv1.ListAuditEventsResponse, error) {
	if err := s.record(ctx, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.audit = in
	s.mu.Unlock()
	return &authv1.ListAuditEventsResponse{
		Events: []*authv1.AuditEvent{
			{Id: 9, OccurredAt: "2026-11-22T09:00:00Z", Action: "user.disabled", ActorKind: "staff", ActorId: "keycloak:user-1", SubjectUserId: suUserID, Reason: suReason, Details: `{"changed":true}`},
			{Id: 8, OccurredAt: "2026-11-22T08:00:00Z", Action: "user.enabled", ActorKind: "system", OrgId: srOrgID, Details: "not json"},
		},
		NextPageToken: "next-2",
	}, nil
}

// newStaffUserRouteEnv builds the edge over the in-process account stub. withUsers
// wires the staff account port (the service token is set on the adapter);
// withOIDC wires the Keycloak verifier.
func newStaffUserRouteEnv(t *testing.T, withUsers, withOIDC bool, stub *suStub) *srEnv {
	t.Helper()
	clock := &fakeClock{now: testStart}
	key := newRSAKey(t)
	jwks := newJWKSServer(t, map[string]*rsa.PublicKey{srKeyID: &key.PublicKey})

	var verifier *staffoidc.Verifier
	if withOIDC {
		v, err := staffoidc.New(staffoidc.Config{
			Issuer:        testIssuer,
			Audiences:     []string{testAudience},
			AllowedGroups: []string{"dev", "admins"},
			JWKSURL:       jwks.URL,
			Clock:         clock,
		})
		if err != nil {
			t.Fatalf("staffoidc.New: %v", err)
		}
		verifier = v
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv1.RegisterStaffUserServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := authclient.NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.StaffServiceToken = srServiceToken

	deps := application.Deps{Limiter: ratelimit.New(ratelimiting.NewMemoryLimiter())}
	if withUsers {
		deps.StaffUsers = client
	}
	srv := New(application.NewService(deps), Options{JWTSecret: testHS256, StaffOIDC: verifier})
	return &srEnv{base: serveOnLoopback(t, srv), key: key, clock: clock}
}

// suRoutes is every staff account and audit route with a valid body for writes.
var suRoutes = []struct {
	name   string
	method string
	path   string
	body   string
}{
	{"list users", http.MethodGet, "/api/v1/staff/users", ""},
	{"get user", http.MethodGet, "/api/v1/staff/users/" + suUserID, ""},
	{"disable user", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/disable", `{"reason":"` + suReason + `"}`},
	{"enable user", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/enable", `{"reason":"` + suReason + `"}`},
	{"audit events", http.MethodGet, "/api/v1/staff/audit-events?org_id=" + srOrgID, ""},
}

func TestStaffUserRoutesAbsentWithoutConfiguration(t *testing.T) {
	cases := []struct {
		name     string
		withUser bool
		withOIDC bool
	}{
		{"no staff service token", false, true},
		{"no staff OIDC verifier", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &suStub{}
			env := newStaffUserRouteEnv(t, c.withUser, c.withOIDC, stub)
			token := env.staffToken(t, "user-1")

			get := env.do(t, http.MethodGet, "/api/v1/staff/users", "", token, nil)
			if get.Status != http.StatusNotFound {
				t.Fatalf("GET status = %d, want 404", get.Status)
			}
			post := env.do(t, http.MethodPost, "/api/v1/staff/users/"+suUserID+"/disable", `{"reason":"x"}`, token, nil)
			if post.Status != http.StatusMethodNotAllowed {
				t.Fatalf("POST status = %d, want 405 from the mux", post.Status)
			}
			if stub.callCount() != 0 {
				t.Fatalf("upstream calls = %d, want 0", stub.callCount())
			}
		})
	}
}

func TestStaffUserRoutesRequireAKeycloakStaffToken(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)
	wrongKey := newRSAKey(t)
	wrongSigned := signRS256(t, wrongKey, srKeyID, keycloakClaims(env.clock, "dev"))

	for _, route := range suRoutes {
		t.Run(route.name, func(t *testing.T) {
			missing := env.do(t, route.method, route.path, route.body, "", map[string]string{"Content-Type": "application/json"})
			if missing.Status != http.StatusUnauthorized || errorBody(t, missing) != "missing bearer token" {
				t.Fatalf("no token: %d %q", missing.Status, missing.Body)
			}
			forged := env.do(t, route.method, route.path, route.body, wrongSigned, map[string]string{"Content-Type": "application/json"})
			if forged.Status != http.StatusUnauthorized || errorBody(t, forged) != "invalid token" {
				t.Fatalf("forged token: %d %q", forged.Status, forged.Body)
			}
		})
	}
	if stub.callCount() != 0 {
		t.Fatalf("upstream calls = %d, want 0", stub.callCount())
	}
}

func TestStaffListUsersForwardsFiltersAndPage(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)

	resp := env.do(t, http.MethodGet, "/api/v1/staff/users?q=%20ada%20&status=disabled&page_token=tok-1&page_size=25", "", env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	if resp.CacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", resp.CacheControl)
	}
	var got struct {
		Users []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"users"`
		NextPageToken string `json:"next_page_token"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Users) != 1 || got.Users[0].ID != suUserID || got.NextPageToken != "next-1" {
		t.Fatalf("body = %q", resp.Body)
	}

	stub.mu.Lock()
	list := stub.list
	stub.mu.Unlock()
	if list.GetQuery() != "ada" || list.GetStatus() != "disabled" || list.GetPageToken() != "tok-1" || list.GetPageSize() != 25 {
		t.Fatalf("upstream request = %+v", list)
	}
	if v, _ := stub.meta(stub.md, "x-staff-subject"); v != "keycloak:user-1" {
		t.Fatalf("staff subject = %q", v)
	}
	if v, _ := stub.meta(stub.md, "x-orbit-service-token"); v != srServiceToken {
		t.Fatalf("service token metadata = %q", v)
	}
	if _, ok := stub.meta(stub.md, "x-staff-reason-bin"); ok {
		t.Fatal("a read must not carry a reason")
	}
}

func TestStaffGetUserReturnsAccountAndMemberships(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)

	resp := env.do(t, http.MethodGet, "/api/v1/staff/users/"+suUserID, "", env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	var got struct {
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
		Memberships []struct {
			OrgID string `json:"org_id"`
			Role  string `json:"role"`
		} `json:"memberships"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.User.ID != suUserID || got.User.Username != "ada" || len(got.Memberships) != 1 || got.Memberships[0].OrgID != srOrgID || got.Memberships[0].Role != "owner" {
		t.Fatalf("body = %q", resp.Body)
	}
	if stub.getID != suUserID {
		t.Fatalf("upstream user id = %q", stub.getID)
	}
}

func TestStaffDisableAndEnableWriteTheReasonAndAnswerTheAccount(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")

	// The body's actor field is ignored: the subject comes from the token.
	body := `{"reason":"  ` + suReason + `  ","actor":"keycloak:evil"}`
	disabled := env.do(t, http.MethodPost, "/api/v1/staff/users/"+suUserID+"/disable", body, token, map[string]string{"Content-Type": "application/json"})
	if disabled.Status != http.StatusOK {
		t.Fatalf("disable status = %d (body %q)", disabled.Status, disabled.Body)
	}
	var user struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(disabled.Body), &user); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if user.ID != suUserID || user.Status != "disabled" {
		t.Fatalf("disable answered %q, want the account as it is afterwards", disabled.Body)
	}
	if strings.Contains(disabled.Body, suReason) {
		t.Fatalf("the reason must not be echoed: %q", disabled.Body)
	}
	stub.mu.Lock()
	writeMD := stub.writeMD
	stub.mu.Unlock()
	if v, _ := stub.meta(writeMD, "x-staff-subject"); v != "keycloak:user-1" {
		t.Fatalf("staff subject = %q, want keycloak:user-1 (never the body)", v)
	}
	if v, ok := stub.meta(writeMD, "x-staff-reason-bin"); !ok || v != suReason {
		t.Fatalf("reason metadata = %q (present %v), want trimmed %q", v, ok, suReason)
	}

	enabled := env.do(t, http.MethodPost, "/api/v1/staff/users/"+suUserID+"/enable", `{"reason":"`+suReason+`"}`, token, map[string]string{"Content-Type": "application/json"})
	if enabled.Status != http.StatusOK || !strings.Contains(enabled.Body, `"status":"active"`) {
		t.Fatalf("enable = %d %q", enabled.Status, enabled.Body)
	}
	stub.mu.Lock()
	writes := stub.writes
	stub.mu.Unlock()
	if len(writes) != 2 || writes[0] != "disable "+suUserID || writes[1] != "enable "+suUserID {
		t.Fatalf("upstream writes = %v", writes)
	}
}

func TestStaffAuditEventsFiltersAndKeepsOnlyDocumentedFields(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")

	resp := env.do(t, http.MethodGet, "/api/v1/staff/audit-events?org_id="+srOrgID+"&page_size=10", "", token, nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	stub.mu.Lock()
	audit := stub.audit
	stub.mu.Unlock()
	if audit.GetOrgId() != srOrgID || audit.GetUserId() != "" || audit.GetPageSize() != 10 {
		t.Fatalf("upstream request = %+v", audit)
	}
	if v, ok := stub.meta(stub.md, "x-staff-reason-bin"); ok {
		t.Fatalf("a read must not carry a reason, got %q", v)
	}

	var got struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &got); err != nil || len(got.Events) != 2 {
		t.Fatalf("decode %q: %v", resp.Body, err)
	}
	// Only the documented keys leave the edge: no hash, token or other column.
	allowed := []string{"id", "occurred_at", "action", "actor_kind", "actor_id", "org_id", "subject_user_id", "invite_id", "reason", "details"}
	for key := range got.Events[0] {
		if !slices.Contains(allowed, key) {
			t.Fatalf("undocumented audit key %q in %q", key, resp.Body)
		}
	}
	if details, ok := got.Events[0]["details"].(map[string]any); !ok || details["changed"] != true {
		t.Fatalf("details = %#v, want the JSON object", got.Events[0]["details"])
	}
	if details, ok := got.Events[1]["details"].(map[string]any); !ok || len(details) != 0 {
		t.Fatalf("non-object details = %#v, want {}", got.Events[1]["details"])
	}

	userResp := env.do(t, http.MethodGet, "/api/v1/staff/audit-events?user_id="+suUserID, "", token, nil)
	if userResp.Status != http.StatusOK {
		t.Fatalf("user filter status = %d (body %q)", userResp.Status, userResp.Body)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.audit.GetUserId() != suUserID || stub.audit.GetOrgId() != "" {
		t.Fatalf("user filter upstream request = %+v", stub.audit)
	}
}

func TestStaffUserInputValidationAnswersBeforeUpstream(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		body    string
		status  int
		message string
	}{
		{"get user with a non-uuid id", http.MethodGet, "/api/v1/staff/users/not-a-uuid", "", http.StatusBadRequest, "user_id must be a UUID"},
		{"disable with a non-uuid id", http.MethodPost, "/api/v1/staff/users/not-a-uuid/disable", `{"reason":"x"}`, http.StatusBadRequest, "user_id must be a UUID"},
		{"disable without reason", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/disable", `{}`, http.StatusBadRequest, "reason is required"},
		{"enable with a blank reason", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/enable", `{"reason":"   "}`, http.StatusBadRequest, "reason is required"},
		{"enable with an overlong reason", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/enable", `{"reason":"` + strings.Repeat("r", 501) + `"}`, http.StatusBadRequest, "reason is too long"},
		{"disable with no body", http.MethodPost, "/api/v1/staff/users/" + suUserID + "/disable", ``, http.StatusBadRequest, "invalid json"},
		{"list with a non-integer page size", http.MethodGet, "/api/v1/staff/users?page_size=abc", "", http.StatusBadRequest, "page_size must be an integer"},
		{"list with a page size above 100", http.MethodGet, "/api/v1/staff/users?page_size=101", "", http.StatusBadRequest, "page_size must be between 0 and 100"},
		{"list with a negative page size", http.MethodGet, "/api/v1/staff/users?page_size=-1", "", http.StatusBadRequest, "page_size must be between 0 and 100"},
		{"audit without a filter", http.MethodGet, "/api/v1/staff/audit-events", "", http.StatusBadRequest, "org_id or user_id is required"},
		{"audit with a non-uuid org", http.MethodGet, "/api/v1/staff/audit-events?org_id=org-1", "", http.StatusBadRequest, "org_id must be a UUID"},
		{"audit with a non-uuid user", http.MethodGet, "/api/v1/staff/audit-events?user_id=user-1", "", http.StatusBadRequest, "user_id must be a UUID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &suStub{}
			env := newStaffUserRouteEnv(t, true, true, stub)
			resp := env.do(t, tc.method, tc.path, tc.body, env.staffToken(t, "user-1"), map[string]string{"Content-Type": "application/json"})
			expectError(t, resp, tc.status, tc.message)
			if stub.callCount() != 0 {
				t.Fatalf("upstream calls = %d, want 0", stub.callCount())
			}
		})
	}
}

func TestStaffUserUpstreamErrorsMapLikeTheStaffOrgRoutes(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		status  int
		message string
	}{
		{"not found", status.Error(codes.NotFound, "account not found"), http.StatusNotFound, "account not found"},
		{"failed precondition is a conflict", status.Error(codes.FailedPrecondition, "account is pending"), http.StatusConflict, "account is pending"},
		{"invalid argument", status.Error(codes.InvalidArgument, "page_size too large"), http.StatusBadRequest, "page_size too large"},
		{"permission denied hides as upstream error", status.Error(codes.PermissionDenied, "staff only"), http.StatusBadGateway, "upstream error"},
		{"unavailable", status.Error(codes.Unavailable, "down"), http.StatusServiceUnavailable, "staff service unavailable"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: reset"), http.StatusBadGateway, "upstream error"},
	}
	for _, route := range suRoutes {
		for _, tc := range cases {
			t.Run(route.name+" "+tc.name, func(t *testing.T) {
				stub := &suStub{err: tc.err}
				env := newStaffUserRouteEnv(t, true, true, stub)
				resp := env.do(t, route.method, route.path, route.body, env.staffToken(t, "user-1"), map[string]string{"Content-Type": "application/json"})
				expectError(t, resp, tc.status, tc.message)
			})
		}
	}
}

func TestStaffUserRoutesEnforceTheStaffBudget(t *testing.T) {
	stub := &suStub{}
	env := newStaffUserRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")
	for i := 0; i < domain.StaffOrgRouteLimit; i++ {
		resp := env.do(t, http.MethodGet, "/api/v1/staff/users", "", token, nil)
		if resp.Status != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 within the budget", i+1, resp.Status)
		}
	}
	over := env.do(t, http.MethodGet, "/api/v1/staff/users", "", token, nil)
	if over.Status != http.StatusTooManyRequests {
		t.Fatalf("request past the budget status = %d, want 429", over.Status)
	}
}
