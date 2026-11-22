package httpapi

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	ratelimiting "github.com/manovaspace/orbit-kit/ratelimiting"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/staffoidc"
)

const (
	srServiceToken = "service-token-test"
	srKeyID        = "kid-1"
	srOrgID        = "7d9c2c4e-6b1a-4f0e-9a51-2f3d8e6b7c10"
	srReason       = "support ticket 4411"
	srProvisionOK  = `{"name":"Acme","slug":" acme ","owner_phone":"+989120000000","idempotency_key":"key-1","reason":"  support ticket 4411  "}`
)

// srStub is the in-process orbit-auth StaffOrgService. It records the metadata and
// the requests it receives and answers success unless err is set.
type srStub struct {
	authv1.UnimplementedStaffOrgServiceServer

	mu        sync.Mutex
	err       error
	empty     bool
	calls     int
	md        metadata.MD
	provision *authv1.ProvisionOrganizationRequest
	getOrgID  string
	reinvite  *authv1.ReinviteOwnerRequest
}

func (s *srStub) record(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.md, _ = metadata.FromIncomingContext(ctx)
	return s.err
}

func (s *srStub) meta(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.md.Get(key)
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (s *srStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *srStub) ProvisionOrganization(ctx context.Context, in *authv1.ProvisionOrganizationRequest) (*authv1.ProvisionOrganizationResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.provision = in
	s.mu.Unlock()
	invite := &authv1.StaffInvite{Id: "invite-1", Role: "owner", ExpiresAt: "2026-11-29T10:00:00Z"}
	resp := &authv1.ProvisionOrganizationResponse{
		Organization: &authv1.StaffOrganization{Id: srOrgID, Name: in.GetName(), Slug: "acme", Status: "active", CreatedAt: "2026-11-22T10:00:00Z"},
		OwnerInvite:  invite,
	}
	if in.GetOwnerPhone() != "" {
		invite.Phone = in.GetOwnerPhone()
		resp.Token = "raw-owner-token"
	} else {
		invite.Email = in.GetOwnerEmail()
	}
	return resp, nil
}

func (s *srStub) GetOrganization(ctx context.Context, in *authv1.GetOrganizationRequest) (*authv1.GetOrganizationResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.getOrgID = in.GetOrgId()
	empty := s.empty
	s.mu.Unlock()
	if empty {
		return &authv1.GetOrganizationResponse{Organization: &authv1.StaffOrganization{Id: in.GetOrgId(), Slug: "acme", Status: "active"}}, nil
	}
	return &authv1.GetOrganizationResponse{
		Organization:   &authv1.StaffOrganization{Id: in.GetOrgId(), Name: "Acme", Slug: "acme", Status: "active", MemberCount: 1, OwnerUserIds: []string{"user-owner"}},
		Members:        []*authv1.StaffMember{{UserId: "user-owner", Role: "owner", Status: "active", JoinedAt: "2026-11-22T10:00:00Z"}},
		PendingInvites: []*authv1.StaffInvite{{Id: "invite-2", Email: "pending@example.com", Role: "member", ExpiresAt: "2026-11-29T10:00:00Z"}},
	}, nil
}

func (s *srStub) ReinviteOwner(ctx context.Context, in *authv1.ReinviteOwnerRequest) (*authv1.ReinviteOwnerResponse, error) {
	if err := s.record(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.reinvite = in
	s.mu.Unlock()
	invite := &authv1.StaffInvite{Id: "invite-3", Role: "owner", ExpiresAt: "2026-11-29T10:00:00Z"}
	resp := &authv1.ReinviteOwnerResponse{Invite: invite}
	if in.GetOwnerPhone() != "" {
		invite.Phone = in.GetOwnerPhone()
		resp.Token = "raw-reinvite-token"
	} else {
		invite.Email = in.GetOwnerEmail()
	}
	return resp, nil
}

// srEnv is the real HTTP edge over the in-process staff stub, with a Keycloak
// verifier backed by a JWKS server.
type srEnv struct {
	base  string
	key   *rsa.PrivateKey
	clock *fakeClock
	stub  *srStub
}

// newStaffRouteEnv builds the edge. withOrgs wires the staff port (the service
// token is set on the adapter); withOIDC wires the Keycloak verifier.
func newStaffRouteEnv(t *testing.T, withOrgs, withOIDC bool, stub *srStub) *srEnv {
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
	authv1.RegisterStaffOrgServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := authclient.NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	client.StaffServiceToken = srServiceToken

	deps := application.Deps{Limiter: ratelimit.New(ratelimiting.NewMemoryLimiter())}
	if withOrgs {
		deps.StaffOrgs = client
	}
	srv := New(application.NewService(deps), Options{JWTSecret: testHS256, StaffOIDC: verifier})
	return &srEnv{base: serveOnLoopback(t, srv), key: key, clock: clock, stub: stub}
}

// staffToken signs a Keycloak staff token for sub with the given groups.
func (e *srEnv) staffToken(t *testing.T, sub string, groups ...string) string {
	t.Helper()
	if len(groups) == 0 {
		groups = []string{"dev"}
	}
	claims := keycloakClaims(e.clock, groups...)
	claims["sub"] = sub
	return signRS256(t, e.key, srKeyID, claims)
}

func (e *srEnv) do(t *testing.T, method, path, body, token string, extra map[string]string) response {
	t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	for k, v := range extra {
		hdr[k] = v
	}
	return send(t, e.base, method, path, body, hdr)
}

// errorBody decodes the {"error": ...} envelope.
func errorBody(t *testing.T, resp response) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("decode error body %q: %v", resp.Body, err)
	}
	return body.Error
}

func expectError(t *testing.T, resp response, status int, message string) {
	t.Helper()
	if resp.Status != status {
		t.Fatalf("status = %d, want %d (body %q)", resp.Status, status, resp.Body)
	}
	if got := errorBody(t, resp); got != message {
		t.Fatalf("error = %q, want %q", got, message)
	}
}

func TestStaffRoutesAbsentWithoutConfiguration(t *testing.T) {
	cases := []struct {
		name     string
		withOrgs bool
		withOIDC bool
	}{
		{"no staff service token", false, true},
		{"no staff OIDC verifier", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &srStub{}
			env := newStaffRouteEnv(t, c.withOrgs, c.withOIDC, stub)
			token := env.staffToken(t, "user-1")

			get := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", token, nil)
			if get.Status != http.StatusNotFound {
				t.Fatalf("GET status = %d, want 404", get.Status)
			}
			// An unregistered POST path answers 405 from the mux, as every unregistered
			// POST path does: the GET catch-all makes the path known with GET only.
			post := env.do(t, http.MethodPost, "/api/v1/staff/orgs", srProvisionOK, token, nil)
			if post.Status != http.StatusMethodNotAllowed {
				t.Fatalf("POST status = %d, want 405 from the mux", post.Status)
			}
			if stub.callCount() != 0 {
				t.Fatalf("upstream calls = %d, want 0", stub.callCount())
			}
		})
	}
}

func TestStaffProvisionPhoneOwnerSendsMetadataAndReturnsTokenOnce(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)

	body := `{"name":"Acme","slug":" acme ","owner_phone":"+989120000000","idempotency_key":"key-1","reason":"  support ticket 4411  ","actor":"keycloak:evil"}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", resp.Status, resp.Body)
	}
	if resp.CacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", resp.CacheControl)
	}

	var got struct {
		Organization struct {
			ID string `json:"id"`
		} `json:"organization"`
		OwnerInvite struct {
			Phone string `json:"phone"`
			Role  string `json:"role"`
		} `json:"owner_invite"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Organization.ID != srOrgID || got.Token != "raw-owner-token" || got.OwnerInvite.Phone != "+989120000000" {
		t.Fatalf("body = %q", resp.Body)
	}

	if stub.callCount() != 1 {
		t.Fatalf("upstream calls = %d, want 1", stub.callCount())
	}
	if v, _ := stub.meta("x-orbit-service-token"); v != srServiceToken {
		t.Fatalf("service token metadata = %q", v)
	}
	if v, _ := stub.meta("x-staff-subject"); v != "keycloak:user-1" {
		t.Fatalf("staff subject metadata = %q, want keycloak:user-1 (never the body)", v)
	}
	if v, ok := stub.meta("x-staff-reason-bin"); !ok || v != srReason {
		t.Fatalf("reason metadata = %q (present %v), want trimmed %q", v, ok, srReason)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.provision.GetName() != "Acme" || stub.provision.GetSlug() != "acme" ||
		stub.provision.GetOwnerPhone() != "+989120000000" || stub.provision.GetOwnerEmail() != "" ||
		stub.provision.GetIdempotencyKey() != "key-1" {
		t.Fatalf("upstream request = %+v", stub.provision)
	}
}

func TestStaffProvisionEmailOwnerOmitsToken(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)

	body := `{"name":"Acme","owner_email":"owner@example.com","idempotency_key":"key-2","reason":"new client"}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", resp.Status, resp.Body)
	}
	if strings.Contains(resp.Body, `"token"`) {
		t.Fatalf("email owner must not get a token: %q", resp.Body)
	}
	if !strings.Contains(resp.Body, `"email":"owner@example.com"`) {
		t.Fatalf("owner_invite missing email: %q", resp.Body)
	}
}

func TestStaffGetOrgReturnsDetailWithoutReason(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)

	resp := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.Status, resp.Body)
	}
	if resp.CacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", resp.CacheControl)
	}
	var got struct {
		Organization struct {
			OwnerUserIDs []string `json:"owner_user_ids"`
		} `json:"organization"`
		Members        []map[string]any `json:"members"`
		PendingInvites []map[string]any `json:"pending_invites"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(got.Members) != 1 || got.Members[0]["user_id"] != "user-owner" || len(got.PendingInvites) != 1 {
		t.Fatalf("body = %q", resp.Body)
	}
	if strings.Contains(resp.Body, "token") {
		t.Fatalf("read must never carry a token: %q", resp.Body)
	}
	stub.mu.Lock()
	if stub.getOrgID != srOrgID {
		t.Fatalf("upstream org id = %q", stub.getOrgID)
	}
	stub.mu.Unlock()
	if v, _ := stub.meta("x-staff-subject"); v != "keycloak:user-1" {
		t.Fatalf("staff subject metadata = %q", v)
	}
	if _, ok := stub.meta("x-staff-reason-bin"); ok {
		t.Fatal("a read must not carry a reason")
	}
}

func TestStaffGetOrgEmptyListsAreArrays(t *testing.T) {
	stub := &srStub{empty: true}
	env := newStaffRouteEnv(t, true, true, stub)

	resp := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusOK {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	for _, want := range []string{`"members":[]`, `"pending_invites":[]`, `"owner_user_ids":[]`} {
		if !strings.Contains(resp.Body, want) {
			t.Fatalf("body %q lacks %s", resp.Body, want)
		}
	}
}

func TestStaffReinviteOwnerPhoneReturnsToken(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)

	body := `{"owner_phone":"+989121111111","reason":"  owner lost the link  "}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs/"+srOrgID+"/owner-invites", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", resp.Status, resp.Body)
	}
	if resp.CacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", resp.CacheControl)
	}
	if !strings.Contains(resp.Body, `"token":"raw-reinvite-token"`) {
		t.Fatalf("body = %q", resp.Body)
	}
	if v, ok := stub.meta("x-staff-reason-bin"); !ok || v != "owner lost the link" {
		t.Fatalf("reason metadata = %q (present %v), want trimmed reason", v, ok)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.reinvite.GetOrgId() != srOrgID || stub.reinvite.GetOwnerPhone() != "+989121111111" {
		t.Fatalf("upstream request = %+v", stub.reinvite)
	}
}

func TestStaffReinviteOwnerEmailOmitsToken(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)

	body := `{"owner_email":"owner@example.com","reason":"rotate"}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs/"+srOrgID+"/owner-invites", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %q)", resp.Status, resp.Body)
	}
	if strings.Contains(resp.Body, `"token"`) {
		t.Fatalf("email owner must not get a token: %q", resp.Body)
	}
}

// TestStaffRoutesRefuseNonKeycloakTokens covers the auth gate on all three routes.
// Every refusal happens before the upstream is called.
func TestStaffRoutesRefuseNonKeycloakTokens(t *testing.T) {
	routes := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/staff/orgs", srProvisionOK},
		{http.MethodGet, "/api/v1/staff/orgs/" + srOrgID, ""},
		{http.MethodPost, "/api/v1/staff/orgs/" + srOrgID + "/owner-invites", `{"owner_email":"o@example.com","reason":"r"}`},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			stub := &srStub{}
			env := newStaffRouteEnv(t, true, true, stub)

			hs256Staff := signTestJWT(t, jwt.MapClaims{
				"sub":           "user-1",
				"staff_subject": "legacy-staff",
				"is_staff":      true,
			}, testHS256)
			hs256Tenant := signTestJWT(t, jwt.MapClaims{"sub": "tenant-user"}, testHS256)

			wrongAudience := keycloakClaims(env.clock, "dev")
			wrongAudience["azp"] = "other-client"
			wrongAudience["aud"] = "other-client"

			cases := []struct {
				name   string
				token  string
				status int
				msg    string
			}{
				{"no bearer", "", http.StatusUnauthorized, "missing bearer token"},
				{"HS256 staff token with HS256 staff enabled", hs256Staff, http.StatusUnauthorized, "invalid token"},
				{"HS256 tenant token", hs256Tenant, http.StatusUnauthorized, "invalid token"},
				{"RS256 without allowed group", env.staffToken(t, "user-1", "users"), http.StatusForbidden, "staff access required"},
				{"RS256 wrong audience", signRS256(t, env.key, srKeyID, wrongAudience), http.StatusUnauthorized, "invalid token"},
			}
			for _, c := range cases {
				before := stub.callCount()
				resp := env.do(t, route.method, route.path, route.body, c.token, nil)
				expectError(t, resp, c.status, c.msg)
				if resp.CacheControl != "no-store" {
					t.Fatalf("%s: Cache-Control = %q, want no-store", c.name, resp.CacheControl)
				}
				if stub.callCount() != before {
					t.Fatalf("%s: upstream was called", c.name)
				}
			}
		})
	}
}

func TestStaffProvisionValidation(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")

	long := strings.Repeat("r", 501)
	exact := strings.Repeat("r", 500)
	cases := []struct {
		name   string
		body   string
		status int
		msg    string
	}{
		{"invalid json", `{"name":`, http.StatusBadRequest, "invalid json"},
		{"reason missing", `{"name":"A","owner_email":"o@example.com","idempotency_key":"k"}`, http.StatusBadRequest, "reason is required"},
		{"reason blank", `{"name":"A","owner_email":"o@example.com","idempotency_key":"k","reason":"   "}`, http.StatusBadRequest, "reason is required"},
		{"reason too long", `{"name":"A","owner_email":"o@example.com","idempotency_key":"k","reason":"` + long + `"}`, http.StatusBadRequest, "reason is too long"},
		{"both owners", `{"name":"A","owner_email":"o@example.com","owner_phone":"+989120000000","idempotency_key":"k","reason":"r"}`, http.StatusBadRequest, "set exactly one of owner_email or owner_phone"},
		{"no owner", `{"name":"A","idempotency_key":"k","reason":"r"}`, http.StatusBadRequest, "set exactly one of owner_email or owner_phone"},
		{"idempotency key missing", `{"name":"A","owner_email":"o@example.com","reason":"r"}`, http.StatusBadRequest, "idempotency_key is required"},
		{"idempotency key too long", `{"name":"A","owner_email":"o@example.com","idempotency_key":"` + strings.Repeat("k", 129) + `","reason":"r"}`, http.StatusBadRequest, "idempotency_key is too long"},
		{"reason only in header", `{"name":"A","owner_email":"o@example.com","idempotency_key":"k"}`, http.StatusBadRequest, "reason is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			extra := map[string]string{}
			if c.name == "reason only in header" {
				extra["X-Staff-Reason"] = "header reason"
			}
			resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs", c.body, token, extra)
			expectError(t, resp, c.status, c.msg)
		})
	}
	if stub.callCount() != 0 {
		t.Fatalf("invalid requests reached upstream %d times", stub.callCount())
	}

	// The reason limit is counted in characters, so 500 is accepted.
	body := `{"name":"A","owner_email":"o@example.com","idempotency_key":"k","reason":"` + exact + `"}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs", body, token, nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("500-character reason: status = %d, want 201 (body %q)", resp.Status, resp.Body)
	}
}

func TestStaffPathAndReasonValidation(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")

	resp := env.do(t, http.MethodGet, "/api/v1/staff/orgs/not-a-uuid", "", token, nil)
	expectError(t, resp, http.StatusBadRequest, "org_id must be a UUID")

	resp = env.do(t, http.MethodPost, "/api/v1/staff/orgs/not-a-uuid/owner-invites", `{"owner_email":"o@example.com","reason":"r"}`, token, nil)
	expectError(t, resp, http.StatusBadRequest, "org_id must be a UUID")

	resp = env.do(t, http.MethodPost, "/api/v1/staff/orgs/"+srOrgID+"/owner-invites", `{"owner_email":"o@example.com"}`, token, nil)
	expectError(t, resp, http.StatusBadRequest, "reason is required")

	if stub.callCount() != 0 {
		t.Fatalf("invalid requests reached upstream %d times", stub.callCount())
	}
}

func TestStaffUpstreamErrorMapping(t *testing.T) {
	const upstreamDetail = "secret upstream detail"
	cases := []struct {
		name    string
		code    codes.Code
		status  int
		wantMsg string
	}{
		// Client-meaningful codes pass the upstream message through, as the other org routes do.
		{"invalid argument", codes.InvalidArgument, http.StatusBadRequest, upstreamDetail},
		{"not found", codes.NotFound, http.StatusNotFound, upstreamDetail},
		{"already exists", codes.AlreadyExists, http.StatusConflict, upstreamDetail},
		{"failed precondition", codes.FailedPrecondition, http.StatusConflict, upstreamDetail},
		// Service-side failures answer a fixed message that never carries the detail.
		{"unavailable", codes.Unavailable, http.StatusServiceUnavailable, "staff service unavailable"},
		{"unauthenticated", codes.Unauthenticated, http.StatusBadGateway, "upstream error"},
		{"internal", codes.Internal, http.StatusBadGateway, "upstream error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stub := &srStub{err: status.Error(c.code, upstreamDetail)}
			env := newStaffRouteEnv(t, true, true, stub)
			token := env.staffToken(t, "user-1")

			resp := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", token, nil)
			expectError(t, resp, c.status, c.wantMsg)
			if resp.CacheControl != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", resp.CacheControl)
			}

			post := env.do(t, http.MethodPost, "/api/v1/staff/orgs", srProvisionOK, token, nil)
			expectError(t, post, c.status, c.wantMsg)
		})
	}
}

func TestStaffRoutesRateLimitedPerSubject(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	first := env.staffToken(t, "user-1")

	for i := 0; i < 30; i++ {
		resp := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", first, nil)
		if resp.Status != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, resp.Status)
		}
	}
	denied := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", first, nil)
	if denied.Status != http.StatusTooManyRequests {
		t.Fatalf("31st request: status = %d, want 429", denied.Status)
	}
	if denied.CacheControl != "no-store" {
		t.Fatalf("429 Cache-Control = %q, want no-store", denied.CacheControl)
	}

	other := env.do(t, http.MethodGet, "/api/v1/staff/orgs/"+srOrgID, "", env.staffToken(t, "user-2"), nil)
	if other.Status != http.StatusOK {
		t.Fatalf("other subject: status = %d, want 200", other.Status)
	}
}

// accept_url on the staff routes is trimmed and forwarded; an overlong one is a 400
// before orbit-auth is called.
func TestStaffProvisionForwardsAcceptURL(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	body := `{"name":"Acme","owner_email":"owner@example.com","idempotency_key":"key-3","reason":"new client","accept_url":"  https://{slug}.falak.demo.manova.space/invite  "}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if got := stub.provision.GetAcceptUrl(); got != "https://{slug}.falak.demo.manova.space/invite" {
		t.Fatalf("forwarded accept_url = %q", got)
	}
}

func TestStaffOwnerInviteForwardsAcceptURL(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	body := `{"owner_phone":"+989121111111","reason":"rotate","accept_url":"https://acme.falak.demo.manova.space/invite"}`
	resp := env.do(t, http.MethodPost, "/api/v1/staff/orgs/"+srOrgID+"/owner-invites", body, env.staffToken(t, "user-1"), nil)
	if resp.Status != http.StatusCreated {
		t.Fatalf("status = %d (body %q)", resp.Status, resp.Body)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if got := stub.reinvite.GetAcceptUrl(); got != "https://acme.falak.demo.manova.space/invite" {
		t.Fatalf("forwarded accept_url = %q", got)
	}
}

func TestStaffAcceptURLTooLongIs400BeforeUpstream(t *testing.T) {
	stub := &srStub{}
	env := newStaffRouteEnv(t, true, true, stub)
	token := env.staffToken(t, "user-1")
	long := strings.Repeat("u", 501)

	body := `{"name":"Acme","owner_email":"owner@example.com","idempotency_key":"key-4","reason":"r","accept_url":"` + long + `"}`
	expectError(t, env.do(t, http.MethodPost, "/api/v1/staff/orgs", body, token, nil), http.StatusBadRequest, "accept_url is too long")

	body = `{"owner_email":"owner@example.com","reason":"r","accept_url":"` + long + `"}`
	expectError(t, env.do(t, http.MethodPost, "/api/v1/staff/orgs/"+srOrgID+"/owner-invites", body, token, nil), http.StatusBadRequest, "accept_url is too long")

	if stub.callCount() != 0 {
		t.Fatalf("overlong accept_url reached upstream %d times", stub.callCount())
	}
}
