package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ratelimiting "github.com/manovaspace/orbit-rate-limiting"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

const (
	testPendingToken = "tok-pending-secret"
	testUnknownToken = "tok-unknown-secret"
	testPassword     = "correct horse battery"
	testPreviewPath  = "/api/v1/public/invites/preview"
	testAcceptPath   = "/api/v1/public/invites/accept"
	testPreviewBody  = `{"token":"` + testPendingToken + `"}`
	testAcceptBody   = `{"token":"` + testPendingToken + `","password":"` + testPassword + `","display_name":"Sara"}`
)

// inviteOrgsFake stands in for the OrgService port with only the invitation
// write answered. It records what the edge forwarded.
type inviteOrgsFake struct {
	domain.OrgService

	mu       sync.Mutex
	requests []domain.InviteRequest
	tokens   []string
	created  domain.CreatedInvite
	err      error
}

func (f *inviteOrgsFake) InviteMember(_ context.Context, in domain.InviteRequest, accessToken string) (domain.CreatedInvite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, in)
	f.tokens = append(f.tokens, accessToken)
	if f.err != nil {
		return domain.CreatedInvite{}, f.err
	}
	return f.created, nil
}

func (f *inviteOrgsFake) forwarded() ([]domain.InviteRequest, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.InviteRequest(nil), f.requests...), append([]string(nil), f.tokens...)
}

// invitePortFake stands in for the public InviteService port. Only pending tokens
// can be used; every other token gets the not-found answer orbit-auth gives.
type invitePortFake struct {
	mu         sync.Mutex
	pending    map[string]domain.InvitePreview
	previewErr error
	acceptErr  error
	accepted   domain.InviteAcceptance
	previews   []string
	signups    []domain.InviteSignup
}

func newInvitePortFake() *invitePortFake {
	return &invitePortFake{
		pending: map[string]domain.InvitePreview{
			testPendingToken: {OrgID: "org-1", OrgName: "Acme", OrgSlug: "acme", Role: "admin", ExpiresAt: "2026-11-09T10:00:00Z"},
		},
		accepted: domain.InviteAcceptance{UserID: "user-9", OrgID: "org-1"},
	}
}

func (f *invitePortFake) GetInvitePreview(_ context.Context, token string) (domain.InvitePreview, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.previews = append(f.previews, token)
	if f.previewErr != nil {
		return domain.InvitePreview{}, f.previewErr
	}
	preview, ok := f.pending[token]
	if !ok {
		return domain.InvitePreview{}, domain.NewError(domain.KindNotFound, "invite not found")
	}
	return preview, nil
}

func (f *invitePortFake) AcceptInviteWithSignup(_ context.Context, in domain.InviteSignup) (domain.InviteAcceptance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signups = append(f.signups, in)
	if _, ok := f.pending[in.Token]; !ok {
		return domain.InviteAcceptance{}, domain.NewError(domain.KindNotFound, "invite not found")
	}
	if f.acceptErr != nil {
		return domain.InviteAcceptance{}, f.acceptErr
	}
	return f.accepted, nil
}

func (f *invitePortFake) forwardedPreviews() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.previews...)
}

func (f *invitePortFake) forwardedSignups() []domain.InviteSignup {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.InviteSignup(nil), f.signups...)
}

// syncBuffer collects log output written from the handler goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newInviteServer builds the edge with the ports the test supplies. A nil port
// leaves its routes unregistered.
func newInviteServer(orgs domain.OrgService, invites domain.InviteService, limiter domain.Limiter, logger func(string, ...any)) *Server {
	svc := application.NewService(application.Deps{
		Orgs:    orgs,
		Invites: invites,
		Limiter: limiter,
		Assets:  assets.New("openapi"),
		Logger:  logger,
	})
	return New(svc, Options{JWTSecret: "test-secret"})
}

// newInviteTestServer serves the edge's mux over httptest: the same routes,
// budgets and handlers, without the Fiber front.
func newInviteTestServer(t *testing.T, orgs domain.OrgService, invites domain.InviteService, limiter domain.Limiter, logger func(string, ...any)) string {
	t.Helper()
	ts := httptest.NewServer(newInviteServer(orgs, invites, limiter, logger).mux)
	t.Cleanup(ts.Close)
	return ts.URL
}

// awaitSpans waits until the recorder holds want ended spans or a deadline passes.
// A span ends after its response is written, so the check polls.
func awaitSpans(recorder *tracetest.SpanRecorder, want int) []sdktrace.ReadOnlySpan {
	deadline := time.Now().Add(5 * time.Second)
	for {
		spans := recorder.Ended()
		if len(spans) >= want || time.Now().After(deadline) {
			return spans
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// spanText collects the name, status, attributes and event attributes of a span.
func spanText(span sdktrace.ReadOnlySpan) string {
	var b strings.Builder
	b.WriteString(span.Name())
	b.WriteString(span.Status().Description)
	for _, kv := range span.Attributes() {
		b.WriteString(string(kv.Key))
		b.WriteString("=")
		b.WriteString(kv.Value.String())
		b.WriteString("\n")
	}
	for _, event := range span.Events() {
		b.WriteString(event.Name)
		for _, kv := range event.Attributes {
			b.WriteString(kv.Value.String())
		}
	}
	return b.String()
}

func TestCreateInviteForwardsAnEmailWithTheDefaultTier(t *testing.T) {
	orgs := &inviteOrgsFake{created: domain.CreatedInvite{Invite: domain.Invite{
		ID: "invite-1", OrgID: "org-1", Email: "person@example.com", InviterID: "user-1",
		Status: "pending", ExpiresAt: "2026-11-09T10:00:00Z", CreatedAt: "2026-11-02T10:00:00Z",
	}}}
	base := newInviteTestServer(t, orgs, nil, nil, nil)

	got := send(t, base, http.MethodPost, "/api/v1/orgs/org-1/invites", `{"email":" person@example.com "}`, bearer())
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	// An email invitation has no token and keeps the body it always had.
	want := `{"invite":{"id":"invite-1","org_id":"org-1","email":"person@example.com","inviter_id":"user-1","status":"pending","expires_at":"2026-11-09T10:00:00Z","created_at":"2026-11-02T10:00:00Z"}}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	requests, tokens := orgs.forwarded()
	if len(requests) != 1 || requests[0] != (domain.InviteRequest{OrgID: "org-1", Email: "person@example.com", Role: domain.RoleMember}) {
		t.Fatalf("forwarded requests = %+v", requests)
	}
	if len(tokens) != 1 || tokens[0] != testAccessToken {
		t.Fatalf("forwarded access tokens = %q", tokens)
	}
}

func TestCreateInviteForwardsAPhoneAndTierAndReturnsTheTokenOnce(t *testing.T) {
	orgs := &inviteOrgsFake{created: domain.CreatedInvite{
		Invite: domain.Invite{
			ID: "invite-2", OrgID: "org-1", Phone: "+989121234567", Role: "admin", InviterID: "user-1",
			Status: "pending", ExpiresAt: "2026-11-09T10:00:00Z", CreatedAt: "2026-11-02T10:00:00Z",
		},
		Token: "raw-phone-token",
	}}
	base := newInviteTestServer(t, orgs, nil, nil, nil)

	got := send(t, base, http.MethodPost, "/api/v1/orgs/org-1/invites", `{"phone":"+989121234567","role":"admin"}`, bearer())
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	want := `{"invite":{"id":"invite-2","org_id":"org-1","email":"","phone":"+989121234567","role":"admin","inviter_id":"user-1","status":"pending","expires_at":"2026-11-09T10:00:00Z","created_at":"2026-11-02T10:00:00Z"},"token":"raw-phone-token"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	requests, _ := orgs.forwarded()
	if len(requests) != 1 || requests[0] != (domain.InviteRequest{OrgID: "org-1", Phone: "+989121234567", Role: "admin"}) {
		t.Fatalf("forwarded requests = %+v", requests)
	}
}

func TestCreateInviteNeedsExactlyOneContactAndAKnownTier(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"both email and phone", `{"email":"a@example.com","phone":"+989121234567"}`, `{"error":"set exactly one of email or phone"}`},
		{"neither email nor phone", `{"role":"member"}`, `{"error":"set exactly one of email or phone"}`},
		{"blank email is no email", `{"email":"   "}`, `{"error":"set exactly one of email or phone"}`},
		{"unknown tier", `{"email":"a@example.com","role":"superuser"}`, `{"error":"role must be owner, admin or member"}`},
		{"malformed json", `{"email":`, `{"error":"invalid json"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orgs := &inviteOrgsFake{}
			base := newInviteTestServer(t, orgs, nil, nil, nil)

			got := send(t, base, http.MethodPost, "/api/v1/orgs/org-1/invites", tc.body, bearer())
			if got.Status != http.StatusBadRequest || got.Body != tc.want+"\n" {
				t.Fatalf("got %d %q, want 400 %q", got.Status, got.Body, tc.want)
			}
			if requests, _ := orgs.forwarded(); len(requests) != 0 {
				t.Fatalf("orbit-auth was called for an invalid request: %+v", requests)
			}
		})
	}
}

func TestCreateInviteKeepsTheForbiddenAndConflictAnswers(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"member without authority is forbidden", domain.NewError(domain.KindPermissionDenied, "caller lacks organization administration authority"), http.StatusForbidden, `{"error":"caller lacks organization administration authority"}`},
		{"state conflict is a conflict", domain.NewError(domain.KindConflict, "invitation cannot be created now"), http.StatusConflict, `{"error":"invitation cannot be created now"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := newInviteTestServer(t, &inviteOrgsFake{err: tc.err}, nil, nil, nil)

			got := send(t, base, http.MethodPost, "/api/v1/orgs/org-1/invites", `{"email":"a@example.com"}`, bearer())
			if got.Status != tc.wantStatus || got.Body != tc.wantBody+"\n" {
				t.Fatalf("got %d %q, want %d %q", got.Status, got.Body, tc.wantStatus, tc.wantBody)
			}
		})
	}
}

// The preview shows the organization and never the recipient. The port type has
// no recipient field, so the exact body is the whole contract.
func TestPublicInvitePreviewShowsTheOrganizationAndNoRecipient(t *testing.T) {
	base := newInviteTestServer(t, nil, newInvitePortFake(), nil, nil)

	got := send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	want := `{"org_id":"org-1","org_name":"Acme","org_slug":"acme","role":"admin","expires_at":"2026-11-09T10:00:00Z"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	if got.CacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", got.CacheControl)
	}
}

// An expired token and a token that never existed reach the edge as the same
// not-found answer, so the two bodies are byte-identical.
func TestPublicInvitePreviewAnswersExpiredAndUnknownAlike(t *testing.T) {
	base := newInviteTestServer(t, nil, newInvitePortFake(), nil, nil)
	want := `{"error":"invite not found"}` + "\n"

	for _, token := range []string{"tok-expired-secret", testUnknownToken} {
		got := send(t, base, http.MethodPost, testPreviewPath, `{"token":"`+token+`"}`, nil)
		if got.Status != http.StatusNotFound || got.Body != want {
			t.Fatalf("%s: got %d %q, want 404 %q", token, got.Status, got.Body, want)
		}
	}
}

func TestPublicInvitePreviewHidesUpstreamFailures(t *testing.T) {
	port := newInvitePortFake()
	port.previewErr = domain.NewError(domain.KindBadGateway, "upstream error")
	base := newInviteTestServer(t, nil, port, nil, nil)

	got := send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil)
	if got.Status != http.StatusBadGateway || got.Body != `{"error":"upstream error"}`+"\n" {
		t.Fatalf("got %d %q, want 502 upstream error", got.Status, got.Body)
	}
}

func TestPublicInvitePreviewTrimsTheTokenBeforeLookup(t *testing.T) {
	port := newInvitePortFake()
	base := newInviteTestServer(t, nil, port, nil, nil)

	got := send(t, base, http.MethodPost, testPreviewPath, `{"token":"  `+testPendingToken+`  "}`, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if previews := port.forwardedPreviews(); len(previews) != 1 || previews[0] != testPendingToken {
		t.Fatalf("forwarded tokens = %q", previews)
	}
}

func TestPublicInviteAcceptCreatesTheAccountAndForwardsTheFields(t *testing.T) {
	port := newInvitePortFake()
	base := newInviteTestServer(t, nil, port, nil, nil)

	got := send(t, base, http.MethodPost, testAcceptPath, testAcceptBody, nil)
	if got.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", got.Status)
	}
	if want := `{"user_id":"user-9","org_id":"org-1"}` + "\n"; got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	signups := port.forwardedSignups()
	if len(signups) != 1 || signups[0] != (domain.InviteSignup{Token: testPendingToken, Password: testPassword, DisplayName: "Sara"}) {
		t.Fatalf("forwarded signups = %+v", signups)
	}
}

func TestPublicInviteAcceptAnswersEachFailureAsItsStatus(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		acceptErr error
		want      int
		wantBody  string
	}{
		{"existing account is account_exists", testAcceptBody, domain.NewError(domain.KindConflict, "account_exists"), http.StatusConflict, `{"error":"account_exists"}`},
		{"weak password is a bad request", `{"token":"` + testPendingToken + `","password":"short"}`, domain.NewError(domain.KindInvalidArgument, "password must be at least 8 characters"), http.StatusBadRequest, `{"error":"password must be at least 8 characters"}`},
		{"disabled sign-up is forbidden", testAcceptBody, domain.NewError(domain.KindPermissionDenied, "invite sign-up is disabled"), http.StatusForbidden, `{"error":"invite sign-up is disabled"}`},
		{"unusable token is not found", `{"token":"` + testUnknownToken + `","password":"` + testPassword + `"}`, nil, http.StatusNotFound, `{"error":"invite not found"}`},
		{"malformed json is a bad request", `{"token":`, nil, http.StatusBadRequest, `{"error":"invalid json"}`},
		{"a token echoed in a message is redacted", testAcceptBody, domain.NewError(domain.KindInvalidArgument, "bad invite "+testPendingToken), http.StatusBadRequest, `{"error":"bad invite [redacted]"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := newInvitePortFake()
			port.acceptErr = tc.acceptErr
			base := newInviteTestServer(t, nil, port, nil, nil)

			got := send(t, base, http.MethodPost, testAcceptPath, tc.body, nil)
			if got.Status != tc.want || got.Body != tc.wantBody+"\n" {
				t.Fatalf("got %d %q, want %d %q", got.Status, got.Body, tc.want, tc.wantBody)
			}
			if strings.Contains(got.Body, testPendingToken) {
				t.Fatalf("response body carries the invitation token: %q", got.Body)
			}
		})
	}
}

// The token is required in the body. A missing or blank token is a bad request,
// and the port is never asked.
func TestPublicInviteRoutesRequireTheTokenInTheBody(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want string
	}{
		{"preview without a token", testPreviewPath, `{}`, `{"error":"token is required"}`},
		{"preview with a blank token", testPreviewPath, `{"token":"   "}`, `{"error":"token is required"}`},
		{"preview with malformed json", testPreviewPath, `{"token":`, `{"error":"invalid json"}`},
		{"accept without a token", testAcceptPath, `{"password":"` + testPassword + `"}`, `{"error":"token is required"}`},
		{"accept with a blank token", testAcceptPath, `{"token":" ","password":"` + testPassword + `"}`, `{"error":"token is required"}`},
		{"accept with malformed json", testAcceptPath, `{"token":`, `{"error":"invalid json"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := newInvitePortFake()
			base := newInviteTestServer(t, nil, port, nil, nil)

			got := send(t, base, http.MethodPost, tc.path, tc.body, nil)
			if got.Status != http.StatusBadRequest || got.Body != tc.want+"\n" {
				t.Fatalf("got %d %q, want 400 %q", got.Status, got.Body, tc.want)
			}
			if len(port.forwardedPreviews()) != 0 || len(port.forwardedSignups()) != 0 {
				t.Fatal("the invitation port was asked for an invalid request")
			}
		})
	}
}

// The route table carries no path parameter, so no registered template can hold
// the token. Every template is served: the handler runs and rejects the empty body.
func TestPublicInviteRouteTemplatesCarryNoPathParameter(t *testing.T) {
	routes := (&handlers{}).publicInviteRoutes()
	if len(routes) == 0 {
		t.Fatal("no public invitation routes")
	}
	for _, route := range routes {
		if strings.Contains(route.template, "{") {
			t.Fatalf("%s %s has a path parameter; the token must travel in the body", route.method, route.template)
		}
	}

	base := newInviteTestServer(t, nil, newInvitePortFake(), nil, nil)
	for _, route := range routes {
		got := send(t, base, route.method, route.template, `{}`, nil)
		if got.Status != http.StatusBadRequest || got.Body != `{"error":"token is required"}`+"\n" {
			t.Fatalf("%s %s: got %d %q, want the handler's 400", route.method, route.template, got.Status, got.Body)
		}
	}
}

// A token in a URL routes nowhere: the paths that carried it before are not served.
func TestPublicInviteTokenInThePathRoutesNowhere(t *testing.T) {
	base := newInviteTestServer(t, nil, newInvitePortFake(), nil, nil)

	for _, path := range []string{
		"/api/v1/public/invites/" + testPendingToken,
		"/api/v1/public/invites/" + testPendingToken + "/accept",
	} {
		got := send(t, base, http.MethodPost, path, testAcceptBody, nil)
		if got.Status != http.StatusNotFound && got.Status != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s = %d, want no route", path, got.Status)
		}
	}
	if got := send(t, base, http.MethodGet, testPreviewPath, "", nil); got.Status != http.StatusNotFound {
		t.Fatalf("GET preview = %d, want 404", got.Status)
	}
}

func TestPublicInviteRoutesUseTheirOwnPerIPBudgets(t *testing.T) {
	if domain.InviteSignupAcceptIPLimit >= domain.InvitePreviewIPLimit {
		t.Fatalf("accept budget %d must be stricter than preview budget %d", domain.InviteSignupAcceptIPLimit, domain.InvitePreviewIPLimit)
	}
	limiter := &recordingLimiter{allow: true}
	base := newInviteTestServer(t, nil, newInvitePortFake(), limiter, nil)

	send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil)
	send(t, base, http.MethodPost, testAcceptPath, testAcceptBody, nil)

	wantKeys := []string{
		ratelimit.KeyForIP("127.0.0.1", routeInvitePreview),
		ratelimit.KeyForIP("127.0.0.1", routeInviteSignupAccept),
	}
	if len(limiter.keys) != 2 || limiter.keys[0] != wantKeys[0] || limiter.keys[1] != wantKeys[1] {
		t.Fatalf("limiter keys = %v, want %v", limiter.keys, wantKeys)
	}
	if limiter.policies[0] != domain.IPRoutePolicy(routeInvitePreview, domain.InvitePreviewIPLimit) {
		t.Fatalf("preview policy = %+v", limiter.policies[0])
	}
	if limiter.policies[1] != domain.IPRoutePolicy(routeInviteSignupAccept, domain.InviteSignupAcceptIPLimit) {
		t.Fatalf("accept policy = %+v", limiter.policies[1])
	}
}

func TestPublicInvitePreviewIsRateLimitedPerIP(t *testing.T) {
	limiter := ratelimit.New(ratelimiting.NewMemoryLimiter())
	base := newInviteTestServer(t, nil, newInvitePortFake(), limiter, nil)

	for i := 0; i < domain.InvitePreviewIPLimit; i++ {
		got := send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil)
		if got.Status != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, got.Status)
		}
	}
	got := send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil)
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

// The budget is spent before the token is checked, so an unknown token still
// counts against the caller's accept budget.
func TestPublicInviteAcceptIsRateLimitedPerIP(t *testing.T) {
	limiter := ratelimit.New(ratelimiting.NewMemoryLimiter())
	base := newInviteTestServer(t, nil, newInvitePortFake(), limiter, nil)
	unknownAccept := `{"token":"` + testUnknownToken + `","password":"` + testPassword + `"}`

	for i := 0; i < domain.InviteSignupAcceptIPLimit; i++ {
		got := send(t, base, http.MethodPost, testAcceptPath, unknownAccept, nil)
		if got.Status != http.StatusNotFound {
			t.Fatalf("request %d status = %d, want 404", i+1, got.Status)
		}
	}
	got := send(t, base, http.MethodPost, testAcceptPath, unknownAccept, nil)
	if got.Status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", got.Status)
	}
}

// The token and the password travel in request bodies only. This test sends them
// through the full edge stack, the one the binary runs, then reads back every place
// the edge could write them: the application logger, the standard logger, slog,
// the trace spans and the rate-limit keys.
func TestPublicInviteTokenNeverReachesLogsSpansOrLimiterKeys(t *testing.T) {
	var out syncBuffer
	prevWriter := log.Writer()
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(prevWriter) })
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	prevProvider := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevProvider)
		_ = provider.Shutdown(context.Background())
	})

	logger := func(msg string, args ...any) { _, _ = fmt.Fprintln(&out, msg, args) }
	limiter := &recordingLimiter{allow: true}
	// The provider is set before the server is built: the observability middleware
	// reads the global provider when it is constructed.
	base := serveOnLoopback(t, newInviteServer(nil, newInvitePortFake(), limiter, logger))

	requests := []struct{ path, body string }{
		{testPreviewPath, testPreviewBody},
		{testPreviewPath, `{"token":"` + testUnknownToken + `"}`},
		{testAcceptPath, testAcceptBody},
	}
	for _, req := range requests {
		send(t, base, http.MethodPost, req.path, req.body, nil)
	}

	spans := awaitSpans(recorder, len(requests))
	if len(spans) < len(requests) {
		t.Fatalf("recorded %d spans, want %d", len(spans), len(requests))
	}
	sawPreviewPath := false
	for _, span := range spans {
		text := spanText(span)
		if strings.Contains(text, testPreviewPath) {
			sawPreviewPath = true
		}
		for _, secret := range []string{testPendingToken, testPassword} {
			if strings.Contains(text, secret) {
				t.Fatalf("trace span %q carries %q", span.Name(), secret)
			}
		}
	}
	if !sawPreviewPath {
		t.Fatal("no span recorded the preview path, so the span check would prove nothing")
	}

	if len(limiter.keys) != len(requests) {
		t.Fatalf("rate-limit keys = %d, want one per request (%d); the key check would prove nothing", len(limiter.keys), len(requests))
	}
	for _, secret := range []string{testPendingToken, testPassword} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("log output carries %q", secret)
		}
		for _, key := range limiter.keys {
			if strings.Contains(key, secret) {
				t.Fatalf("rate-limit key %q carries %q", key, secret)
			}
		}
	}
}

// Without the port the public routes are unregistered. POST answers 405 because
// the installer's GET catch-all owns the path.
func TestPublicInviteRoutesAreAbsentWithoutTheInvitePort(t *testing.T) {
	base := newInviteTestServer(t, nil, nil, nil, nil)

	if got := send(t, base, http.MethodPost, testPreviewPath, testPreviewBody, nil); got.Status != http.StatusMethodNotAllowed {
		t.Fatalf("preview status = %d, want 405", got.Status)
	}
	if got := send(t, base, http.MethodPost, testAcceptPath, testAcceptBody, nil); got.Status != http.StatusMethodNotAllowed {
		t.Fatalf("accept status = %d, want 405", got.Status)
	}
}
