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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
	"github.com/manovaspace/orbit-api-gateway/internal/domain"
	"github.com/manovaspace/orbit-api-gateway/internal/infrastructure/assets"
	authclient "github.com/manovaspace/orbit-api-gateway/internal/infrastructure/auth"
)

// authUpstreamStub is the in-process orbit-auth AuthService stand-in for the
// Google sign-in and username calls. It answers success unless err is set, and
// records what the adapter forwarded.
type authUpstreamStub struct {
	authv1.UnimplementedAuthServiceServer

	mu            sync.Mutex
	err           error
	startReq      *authv1.StartGoogleSignInRequest
	completeReq   *authv1.CompleteGoogleSignInRequest
	usernameReq   *authv1.SetUsernameRequest
	googleCalls   int
	usernameCalls int
	// inviteResp, when set, is the completion answer instead of the plain one.
	inviteResp            *authv1.CompleteGoogleSignInResponse
	googleAuthorization   string
	usernameAuthorization string
}

func (s *authUpstreamStub) StartGoogleSignIn(ctx context.Context, in *authv1.StartGoogleSignInRequest) (*authv1.StartGoogleSignInResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startReq = in
	s.googleCalls++
	s.googleAuthorization = firstMetadata(ctx, "authorization")
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.StartGoogleSignInResponse{AuthorizationUrl: "https://accounts.example.test/authorize", State: "state-value"}, nil
}

func (s *authUpstreamStub) CompleteGoogleSignIn(ctx context.Context, in *authv1.CompleteGoogleSignInRequest) (*authv1.CompleteGoogleSignInResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completeReq = in
	s.googleCalls++
	s.googleAuthorization = firstMetadata(ctx, "authorization")
	if s.err != nil {
		return nil, s.err
	}
	if s.inviteResp != nil {
		return s.inviteResp, nil
	}
	return &authv1.CompleteGoogleSignInResponse{
		Tokens: &authv1.TokenResponse{
			AccessToken:  "access-google",
			RefreshToken: "refresh-google",
			ExpiresAt:    "2026-11-02T11:00:00Z",
		},
		ReturnTo: "/home",
	}, nil
}

func (s *authUpstreamStub) SetUsername(ctx context.Context, in *authv1.SetUsernameRequest) (*authv1.SetUsernameResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usernameReq = in
	s.usernameCalls++
	s.usernameAuthorization = firstMetadata(ctx, "authorization")
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.SetUsernameResponse{Username: "sara.k"}, nil
}

func (s *authUpstreamStub) googleSeen() (start *authv1.StartGoogleSignInRequest, complete *authv1.CompleteGoogleSignInRequest, calls int, authorization string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startReq, s.completeReq, s.googleCalls, s.googleAuthorization
}

func (s *authUpstreamStub) usernameSeen() (req *authv1.SetUsernameRequest, calls int, authorization string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usernameReq, s.usernameCalls, s.usernameAuthorization
}

// newGoogleEnv starts the real HTTP edge over an in-process gRPC orbit-auth
// stand-in. It wires only the Google sign-in and username ports.
func newGoogleEnv(t *testing.T, stub *authUpstreamStub, limiter domain.Limiter) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, err := authclient.NewClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	svc := application.NewService(application.Deps{
		Google:    client,
		Usernames: client,
		Limiter:   limiter,
		Assets:    assets.New("openapi"),
	})
	return serveOnLoopback(t, New(svc, Options{JWTSecret: "test-secret"}))
}

const (
	googleStartBodyOK    = `{"redirect_uri":"https://app.example.test/callback","return_to":"/home"}`
	googleCompleteBodyOK = `{"state":"state-value","code":"code-value"}`
	googleOffMessage     = `{"error":"google sign-in is off"}` + "\n"
)

func TestGoogleStartReturnsTheRedirectWithNoStore(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeGoogleStart, googleStartBodyOK, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.CacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", got.CacheControl)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("content-type = %q", got.ContentType)
	}
	want := `{"authorization_url":"https://accounts.example.test/authorize","state":"state-value"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	start, _, calls, authorization := stub.googleSeen()
	if calls != 1 || start.GetRedirectUri() != "https://app.example.test/callback" || start.GetReturnTo() != "/home" {
		t.Fatalf("forwarded start = %+v (calls %d)", start, calls)
	}
	if authorization != "" {
		t.Fatalf("google start forwarded a bearer token")
	}
}

func TestGoogleCompleteReturnsTheTokenFieldsReturnToAndNoStore(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeGoogleComplete, googleCompleteBodyOK, nil)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.CacheControl != "no-store" {
		t.Fatalf("cache-control = %q, want no-store", got.CacheControl)
	}
	want := `{"access_token":"access-google","expires_at":"2026-11-02T11:00:00Z","refresh_token":"refresh-google","return_to":"/home"}` + "\n"
	if got.Body != want {
		t.Fatalf("body = %q, want %q", got.Body, want)
	}
	_, complete, _, authorization := stub.googleSeen()
	if complete.GetState() != "state-value" || complete.GetCode() != "code-value" {
		t.Fatalf("forwarded complete = %+v", complete)
	}
	if authorization != "" {
		t.Fatalf("google complete forwarded a bearer token")
	}
}

func TestGoogleRoutesAnswer404WhenGoogleSignInIsOff(t *testing.T) {
	for _, route := range []struct{ path, body string }{
		{routeGoogleStart, googleStartBodyOK},
		{routeGoogleComplete, googleCompleteBodyOK},
	} {
		t.Run(route.path, func(t *testing.T) {
			stub := &authUpstreamStub{err: status.Error(codes.FailedPrecondition, "google sign-in is disabled")}
			base := newGoogleEnv(t, stub, nil)

			got := send(t, base, http.MethodPost, route.path, route.body, nil)
			if got.Status != http.StatusNotFound || got.Body != googleOffMessage {
				t.Fatalf("status = %d body = %q, want 404 %q", got.Status, got.Body, googleOffMessage)
			}
			if got.CacheControl == "no-store" {
				t.Fatalf("an error answer must not set no-store")
			}
		})
	}
}

func TestGoogleCompleteErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "bad state"), http.StatusBadRequest, `{"error":"bad state"}` + "\n"},
		{"unauthenticated", status.Error(codes.Unauthenticated, "sign-in required"), http.StatusUnauthorized, `{"error":"sign-in required"}` + "\n"},
		{"permission denied", status.Error(codes.PermissionDenied, "not allowed"), http.StatusForbidden, `{"error":"not allowed"}` + "\n"},
		{"internal hides the detail", status.Error(codes.Internal, "pg: connection reset"), http.StatusBadGateway, `{"error":"upstream error"}` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &authUpstreamStub{err: tc.err}
			base := newGoogleEnv(t, stub, nil)

			got := send(t, base, http.MethodPost, routeGoogleComplete, googleCompleteBodyOK, nil)
			if got.Status != tc.wantStatus || got.Body != tc.wantBody {
				t.Fatalf("status = %d body = %q, want %d %q", got.Status, got.Body, tc.wantStatus, tc.wantBody)
			}
			if got.CacheControl == "no-store" {
				t.Fatalf("an error answer must not set no-store")
			}
		})
	}
}

func TestGoogleStartErrorMapping(t *testing.T) {
	stub := &authUpstreamStub{err: status.Error(codes.InvalidArgument, "redirect uri not registered")}
	base := newGoogleEnv(t, stub, nil)

	got := send(t, base, http.MethodPost, routeGoogleStart, googleStartBodyOK, nil)
	if got.Status != http.StatusBadRequest || got.Body != `{"error":"redirect uri not registered"}`+"\n" {
		t.Fatalf("status = %d body = %q", got.Status, got.Body)
	}
}

func TestGoogleRoutesRejectMalformedBodiesAndWrongMethods(t *testing.T) {
	stub := &authUpstreamStub{}
	base := newGoogleEnv(t, stub, nil)

	for _, path := range []string{routeGoogleStart, routeGoogleComplete} {
		t.Run("malformed "+path, func(t *testing.T) {
			got := send(t, base, http.MethodPost, path, `{"state":`, nil)
			if got.Status != http.StatusBadRequest || got.Body != `{"error":"invalid json"}`+"\n" {
				t.Fatalf("status = %d body = %q", got.Status, got.Body)
			}
		})
		t.Run("method not allowed "+path, func(t *testing.T) {
			got := send(t, base, http.MethodDelete, path, "", nil)
			if got.Status != http.StatusMethodNotAllowed || !strings.Contains(got.Allow, http.MethodPost) {
				t.Fatalf("status = %d allow = %q, want 405 listing POST", got.Status, got.Allow)
			}
		})
	}
	if _, _, calls, _ := stub.googleSeen(); calls != 0 {
		t.Fatalf("malformed or wrong-method requests reached orbit-auth %d times", calls)
	}
}

func TestGoogleRoutesUseTheAuthGoogleClassPerIP(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		limiter := &recordingLimiter{allow: true}
		stub := &authUpstreamStub{}
		base := newGoogleEnv(t, stub, limiter)

		for _, path := range []string{routeGoogleStart, routeGoogleComplete} {
			body := googleStartBodyOK
			if path == routeGoogleComplete {
				body = googleCompleteBodyOK
			}
			if got := send(t, base, http.MethodPost, path, body, nil); got.Status != http.StatusOK {
				t.Fatalf("%s status = %d", path, got.Status)
			}
		}
		want := domain.ClientKey(domain.ClassAuthGoogle, "127.0.0.1")
		if len(limiter.keys) != 2 || limiter.keys[0] != want || limiter.keys[1] != want {
			t.Fatalf("limiter keys = %v, want two %q", limiter.keys, want)
		}
		for _, policy := range limiter.policies {
			if policy != domain.PolicyFor(domain.ClassAuthGoogle) {
				t.Fatalf("policy = %+v", policy)
			}
		}
		if policy := limiter.policies[0]; policy.Limit != 20 || policy.Window != time.Minute {
			t.Fatalf("policy = %+v, want 20 a minute", policy)
		}
	})

	t.Run("denied before orbit-auth", func(t *testing.T) {
		limiter := &recordingLimiter{allow: false}
		stub := &authUpstreamStub{}
		base := newGoogleEnv(t, stub, limiter)

		got := send(t, base, http.MethodPost, routeGoogleStart, googleStartBodyOK, nil)
		if got.Status != http.StatusTooManyRequests || got.RetryAfter == "" {
			t.Fatalf("status = %d retry-after = %q, want 429 with Retry-After", got.Status, got.RetryAfter)
		}
		if _, _, calls, _ := stub.googleSeen(); calls != 0 {
			t.Fatalf("a denied request reached orbit-auth %d times", calls)
		}
	})
}
