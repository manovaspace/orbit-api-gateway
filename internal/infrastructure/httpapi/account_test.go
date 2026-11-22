package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	ratelimiting "github.com/manovaspace/orbit-kit/ratelimiting"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/ratelimit"
)

// accountStub is the in-process orbit-auth AccountService. It records every
// call, the bearer token it was given and the last request of each method. err,
// when set, is returned by every method.
type accountStub struct {
	authv1.UnimplementedAccountServiceServer

	mu          sync.Mutex
	err         error
	calls       int
	passwords   int
	passwordErr error
	authHeader  string
	signIn      *authv1.GetSignInMethodsResponse
	passwordReq *authv1.SetPasswordRequest
	linkReq     *authv1.StartGoogleLinkRequest
	completeReq *authv1.CompleteGoogleLinkRequest
	revokeReq   *authv1.RevokeAllSessionsRequest
	unlinks     int
}

func (s *accountStub) note(ctx context.Context) error {
	s.calls++
	s.authHeader = firstMetadata(ctx, "authorization")
	return s.err
}

func (s *accountStub) GetSignInMethods(ctx context.Context, _ *authv1.GetSignInMethodsRequest) (*authv1.GetSignInMethodsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	return s.signIn, nil
}

func (s *accountStub) passwordCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.passwords
}

func (s *accountStub) SetPassword(ctx context.Context, in *authv1.SetPasswordRequest) (*authv1.SetPasswordResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwordReq = in
	s.passwords++
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	if s.passwordErr != nil {
		return nil, s.passwordErr
	}
	return &authv1.SetPasswordResponse{}, nil
}

func (s *accountStub) StartGoogleLink(ctx context.Context, in *authv1.StartGoogleLinkRequest) (*authv1.StartGoogleLinkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.linkReq = in
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	return &authv1.StartGoogleLinkResponse{AuthorizationUrl: "https://accounts.example.test/link", State: "link-state"}, nil
}

func (s *accountStub) CompleteGoogleLink(ctx context.Context, in *authv1.CompleteGoogleLinkRequest) (*authv1.CompleteGoogleLinkResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completeReq = in
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	return &authv1.CompleteGoogleLinkResponse{ReturnTo: "/settings", Email: "ada@gmail.test"}, nil
}

func (s *accountStub) UnlinkGoogle(ctx context.Context, _ *authv1.UnlinkGoogleRequest) (*authv1.UnlinkGoogleResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unlinks++
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	return &authv1.UnlinkGoogleResponse{}, nil
}

func (s *accountStub) RevokeAllSessions(ctx context.Context, in *authv1.RevokeAllSessionsRequest) (*authv1.RevokeAllSessionsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeReq = in
	if err := s.note(ctx); err != nil {
		return nil, err
	}
	return &authv1.RevokeAllSessionsResponse{}, nil
}

func (s *accountStub) snapshot() (calls int, authHeader string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.authHeader
}

// newAccountEnv serves the edge over an in-process orbit-auth. The account
// stub and the Google stub share one gRPC server, as they do in orbit-auth.
// limited adds an in-memory limiter.
func newAccountEnv(t *testing.T, acc *accountStub, limited bool) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv1.RegisterAccountServiceServer(gs, acc)
	authv1.RegisterAuthServiceServer(gs, &authUpstreamStub{})
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := authclient.NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	deps := application.Deps{Accounts: client, Google: client}
	if limited {
		deps.Limiter = ratelimit.New(ratelimiting.NewMemoryLimiter())
	}
	return serveOnLoopback(t, New(application.NewService(deps), Options{JWTSecret: "test-secret"}))
}

// testJWT is an unsigned token with the given subject. The edge reads the
// subject for a rate-limit bucket only; it never verifies it.
func testJWT(sub string) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(`{"sub":"` + sub + `"}`))
	return header + "." + payload + ".signature"
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// errorCode reads the optional code of an error body.
func errorCode(t *testing.T, resp response) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("decode error body %q: %v", resp.Body, err)
	}
	return body.Code
}

const (
	accountToken    = "access-token-value"
	passwordOldBody = `{"current_password":"old-pass-1","new_password":"new-pass-2","refresh_token":"refresh-keep"}`
	googleOffJSON   = `{"error":"google sign-in is off"}` + "\n"
)

func TestSignInMethodsReturnsTheFalakShapeWithNulls(t *testing.T) {
	stub := &accountStub{signIn: &authv1.GetSignInMethodsResponse{
		HasPassword:   true,
		Email:         "ada@example.test",
		EmailVerified: true,
		Google: []*authv1.GoogleLink{{
			Email:    "ada@gmail.test",
			LinkedAt: "2026-11-01T10:00:00Z",
		}},
	}}
	base := newAccountEnv(t, stub, false)

	got := send(t, base, http.MethodGet, routeSessionSignInMethods, "", bearerHeader(accountToken))
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, body %q", got.Status, got.Body)
	}
	if got.CacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", got.CacheControl)
	}
	want := `{"email":"ada@example.test","email_verified":true,"google":[{"email":"ada@gmail.test","last_login_at":null,"linked_at":"2026-11-01T10:00:00Z"}],"has_password":true,"mobile":null,"mobile_verified":false,"username":null}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q\nwant   %q", got.Body, want)
	}
	if _, auth := stub.snapshot(); auth != "Bearer "+accountToken {
		t.Fatalf("forwarded authorization = %q", auth)
	}
}

func TestSignInMethodsWithNoGoogleLinkAnswersAnEmptyArray(t *testing.T) {
	stub := &accountStub{signIn: &authv1.GetSignInMethodsResponse{}}
	base := newAccountEnv(t, stub, false)

	got := send(t, base, http.MethodGet, routeSessionSignInMethods, "", bearerHeader(accountToken))
	if got.Status != http.StatusOK || !strings.Contains(got.Body, `"google":[]`) {
		t.Fatalf("status %d body %q", got.Status, got.Body)
	}
}

func TestSessionRoutesRequireABearerToken(t *testing.T) {
	stub := &accountStub{signIn: &authv1.GetSignInMethodsResponse{}}
	base := newAccountEnv(t, stub, false)

	for _, route := range []struct{ method, path, body string }{
		{http.MethodGet, routeSessionSignInMethods, ""},
		{http.MethodPut, routeSessionPassword, passwordOldBody},
		{http.MethodPost, routeSessionGoogleLinkStart, `{"redirect_uri":"https://app.example.test/cb"}`},
		{http.MethodPost, routeSessionGoogleLinkDone, `{"state":"s","code":"c"}`},
		{http.MethodDelete, routeSessionGoogle, ""},
		{http.MethodPost, routeSessionRevokeAll, `{}`},
	} {
		got := send(t, base, route.method, route.path, route.body, nil)
		if got.Status != http.StatusUnauthorized || got.Body != `{"error":"missing bearer token"}`+"\n" {
			t.Fatalf("%s %s: status %d body %q", route.method, route.path, got.Status, got.Body)
		}
	}
	if calls, _ := stub.snapshot(); calls != 0 {
		t.Fatalf("upstream calls without a token = %d, want 0", calls)
	}
}

func TestSetPasswordForwardsEverythingAndAnswersNoContent(t *testing.T) {
	stub := &accountStub{}
	base := newAccountEnv(t, stub, false)

	got := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(accountToken))
	if got.Status != http.StatusNoContent || got.Body != "" {
		t.Fatalf("status %d body %q, want 204 and no body", got.Status, got.Body)
	}
	stub.mu.Lock()
	in := stub.passwordReq
	stub.mu.Unlock()
	if in.GetCurrentPassword() != "old-pass-1" || in.GetNewPassword() != "new-pass-2" || in.GetRefreshToken() != "refresh-keep" {
		t.Fatalf("forwarded password request = %+v", in)
	}
	if _, auth := stub.snapshot(); auth != "Bearer "+accountToken {
		t.Fatalf("forwarded authorization = %q", auth)
	}
}

// accountErrorCases are the upstream refusals of the session routes. Each one
// maps to the status and code Falak branches on.
var accountErrorCases = []struct {
	name   string
	method string
	path   string
	body   string
	err    error
	status int
	code   string
}{
	{"wrong current password", http.MethodPut, routeSessionPassword, passwordOldBody,
		status.Error(codes.Unauthenticated, "invalid credentials"), http.StatusForbidden, "invalid_credentials"},
	{"password required", http.MethodPut, routeSessionPassword, passwordOldBody,
		status.Error(codes.InvalidArgument, "password is required"), http.StatusBadRequest, "password_required"},
	{"password too short", http.MethodPut, routeSessionPassword, passwordOldBody,
		status.Error(codes.InvalidArgument, "password must be at least 8 characters"), http.StatusBadRequest, "password_too_short"},
	{"no password identifier", http.MethodPut, routeSessionPassword, passwordOldBody,
		status.Error(codes.FailedPrecondition, "account needs a verified email, a mobile number or a username to sign in with a password"), http.StatusConflict, "no_password_identifier"},
	{"invalid refresh token", http.MethodPut, routeSessionPassword, passwordOldBody,
		status.Error(codes.Unauthenticated, "invalid refresh token"), http.StatusBadRequest, "invalid_refresh"},
	{"last sign-in method", http.MethodDelete, routeSessionGoogle, "",
		status.Error(codes.FailedPrecondition, "the last sign-in method cannot be removed"), http.StatusConflict, "last_sign_in_method"},
	{"google not linked", http.MethodDelete, routeSessionGoogle, "",
		status.Error(codes.NotFound, "google is not linked"), http.StatusNotFound, "google_not_linked"},
	{"google already linked", http.MethodPost, routeSessionGoogleLinkStart, `{"redirect_uri":"https://app.example.test/cb"}`,
		status.Error(codes.FailedPrecondition, "google is already linked"), http.StatusConflict, "google_already_linked"},
	{"google identity taken", http.MethodPost, routeSessionGoogleLinkDone, `{"state":"s","code":"c"}`,
		status.Error(codes.AlreadyExists, "google account is linked to another user"), http.StatusConflict, "google_identity_taken"},
	{"link state expired", http.MethodPost, routeSessionGoogleLinkDone, `{"state":"s","code":"c"}`,
		status.Error(codes.Unauthenticated, "google sign-in failed"), http.StatusBadRequest, "state_expired"},
}

func TestSessionRoutesMapEachRefusalToItsStatusAndCode(t *testing.T) {
	for _, c := range accountErrorCases {
		t.Run(c.name, func(t *testing.T) {
			stub := &accountStub{err: c.err}
			base := newAccountEnv(t, stub, false)

			got := send(t, base, c.method, c.path, c.body, bearerHeader(accountToken))
			if got.Status != c.status {
				t.Fatalf("status = %d, want %d (body %q)", got.Status, c.status, got.Body)
			}
			if code := errorCode(t, got); code != c.code {
				t.Fatalf("code = %q, want %q (body %q)", code, c.code, got.Body)
			}
		})
	}
}

func TestGoogleOnlySessionRoutesAnswer404WhileGoogleIsOff(t *testing.T) {
	off := status.Error(codes.FailedPrecondition, "google sign-in is off")
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, routeSessionGoogleLinkStart, `{"redirect_uri":"https://app.example.test/cb"}`},
		{http.MethodPost, routeSessionGoogleLinkDone, `{"state":"s","code":"c"}`},
		{http.MethodDelete, routeSessionGoogle, ""},
	} {
		stub := &accountStub{err: off}
		base := newAccountEnv(t, stub, false)

		got := send(t, base, route.method, route.path, route.body, bearerHeader(accountToken))
		if got.Status != http.StatusNotFound || got.Body != googleOffJSON {
			t.Fatalf("%s %s while off: status %d body %q", route.method, route.path, got.Status, got.Body)
		}
	}
}

func TestLinkStartAndCompleteForwardTheirBodies(t *testing.T) {
	stub := &accountStub{}
	base := newAccountEnv(t, stub, false)

	start := send(t, base, http.MethodPost, routeSessionGoogleLinkStart,
		`{"redirect_uri":"https://app.example.test/cb","return_to":"/settings"}`, bearerHeader(accountToken))
	if start.Status != http.StatusOK || start.CacheControl != "no-store" {
		t.Fatalf("start status %d cache %q body %q", start.Status, start.CacheControl, start.Body)
	}
	wantStart := `{"authorization_url":"https://accounts.example.test/link","state":"link-state"}` + "\n"
	if start.Body != wantStart {
		t.Fatalf("start body = %q, want %q", start.Body, wantStart)
	}

	complete := send(t, base, http.MethodPost, routeSessionGoogleLinkDone,
		`{"state":"link-state","code":"google-code"}`, bearerHeader(accountToken))
	if complete.Status != http.StatusOK {
		t.Fatalf("complete status %d body %q", complete.Status, complete.Body)
	}
	wantComplete := `{"email":"ada@gmail.test","return_to":"/settings"}` + "\n"
	if complete.Body != wantComplete {
		t.Fatalf("complete body = %q, want %q", complete.Body, wantComplete)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.linkReq.GetRedirectUri() != "https://app.example.test/cb" || stub.linkReq.GetReturnTo() != "/settings" {
		t.Fatalf("forwarded link start = %+v", stub.linkReq)
	}
	if stub.completeReq.GetState() != "link-state" || stub.completeReq.GetCode() != "google-code" {
		t.Fatalf("forwarded link complete = %+v", stub.completeReq)
	}
}

func TestUnlinkGoogleAnswersNoContent(t *testing.T) {
	stub := &accountStub{}
	base := newAccountEnv(t, stub, false)

	got := send(t, base, http.MethodDelete, routeSessionGoogle, "", bearerHeader(accountToken))
	if got.Status != http.StatusNoContent || got.Body != "" {
		t.Fatalf("status %d body %q, want 204", got.Status, got.Body)
	}
	if stub.unlinks != 1 {
		t.Fatalf("unlink calls = %d, want 1", stub.unlinks)
	}
}

func TestRevokeAllForwardsTheKeptRefreshToken(t *testing.T) {
	stub := &accountStub{}
	base := newAccountEnv(t, stub, false)

	got := send(t, base, http.MethodPost, routeSessionRevokeAll, `{"refresh_token":"refresh-keep"}`, bearerHeader(accountToken))
	if got.Status != http.StatusNoContent {
		t.Fatalf("status %d body %q, want 204", got.Status, got.Body)
	}
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.revokeReq.GetRefreshToken() != "refresh-keep" {
		t.Fatalf("forwarded refresh token = %q", stub.revokeReq.GetRefreshToken())
	}
}

// TestPasswordBudgetIsPerSubject checks the five-per-window budget. The sixth
// attempt by one subject is refused before orbit-auth sees it, and another
// subject keeps its own budget.
func TestPasswordBudgetIsPerSubject(t *testing.T) {
	stub := &accountStub{signIn: &authv1.GetSignInMethodsResponse{}, passwordErr: status.Error(codes.Unauthenticated, "invalid credentials")}
	base := newAccountEnv(t, stub, true)
	subjectA := testJWT("subject-a")

	for i := 0; i < 5; i++ {
		got := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(subjectA))
		if got.Status != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d, want 403", i+1, got.Status)
		}
	}
	limited := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(subjectA))
	if limited.Status != http.StatusTooManyRequests || limited.RetryAfter == "" {
		t.Fatalf("sixth attempt: status %d retry-after %q, want 429", limited.Status, limited.RetryAfter)
	}
	if got := stub.passwordCalls(); got != 5 {
		t.Fatalf("password calls = %d, want 5 (the refused attempt must not reach orbit-auth)", got)
	}

	other := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(testJWT("subject-b")))
	if other.Status != http.StatusForbidden {
		t.Fatalf("another subject: status %d, want 403", other.Status)
	}
}

// TestForgedTokenDoesNotSpendThePasswordBudget checks that a token orbit-auth
// refuses cannot use up the budget of the account its sub claim names.
func TestForgedTokenDoesNotSpendThePasswordBudget(t *testing.T) {
	stub := &accountStub{err: status.Error(codes.Unauthenticated, "invalid access token")}
	base := newAccountEnv(t, stub, true)
	subject := testJWT("subject-a")

	for i := 0; i < 6; i++ {
		got := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(subject))
		if got.Status != http.StatusUnauthorized {
			t.Fatalf("forged attempt %d: status %d, want 401", i+1, got.Status)
		}
	}
	stub.mu.Lock()
	stub.err = nil
	stub.signIn = &authv1.GetSignInMethodsResponse{}
	stub.mu.Unlock()
	got := send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(subject))
	if got.Status != http.StatusNoContent {
		t.Fatalf("real attempt: status %d, want 204", got.Status)
	}
}

// TestSessionSecretsAreNeverLogged runs the secret-bearing routes with a
// capturing logger and checks that no secret value reaches the log.
func TestSessionSecretsAreNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	stub := &accountStub{err: status.Error(codes.Unauthenticated, "invalid credentials")}
	base := newAccountEnv(t, stub, false)
	secrets := []string{"old-pass-1", "new-pass-2", "refresh-keep", "google-code", "link-state", accountToken}

	send(t, base, http.MethodPut, routeSessionPassword, passwordOldBody, bearerHeader(accountToken))
	send(t, base, http.MethodPost, routeSessionGoogleLinkDone, `{"state":"link-state","code":"google-code"}`, bearerHeader(accountToken))
	send(t, base, http.MethodPost, routeSessionRevokeAll, `{"refresh_token":"refresh-keep"}`, bearerHeader(accountToken))

	logged := buf.String()
	for _, secret := range secrets {
		if strings.Contains(logged, secret) {
			t.Fatalf("log contains a secret value")
		}
	}
}
