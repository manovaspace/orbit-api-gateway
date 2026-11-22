package auth

import (
	"context"
	"net"
	"sync"
	"testing"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// googleAuthStub is the orbit-auth AuthService stand-in for the Google sign-in
// and username calls. It records the bearer token the adapter forwarded and the
// request fields it received.
type googleAuthStub struct {
	authv1.UnimplementedAuthServiceServer

	mu            sync.Mutex
	err           error
	startReq      *authv1.StartGoogleSignInRequest
	completeReq   *authv1.CompleteGoogleSignInRequest
	usernameReq   *authv1.SetUsernameRequest
	authorization string
	calls         map[string]string
}

func (s *googleAuthStub) record(ctx context.Context, call string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorization = ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get("authorization"); len(values) > 0 {
			s.authorization = values[0]
		}
	}
	if s.calls == nil {
		s.calls = map[string]string{}
	}
	s.calls[call] = s.authorization
	return s.err
}

func (s *googleAuthStub) StartGoogleSignIn(ctx context.Context, in *authv1.StartGoogleSignInRequest) (*authv1.StartGoogleSignInResponse, error) {
	if err := s.record(ctx, "start"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.startReq = in
	s.mu.Unlock()
	return &authv1.StartGoogleSignInResponse{AuthorizationUrl: "https://accounts.example.test/authorize", State: "state-value"}, nil
}

func (s *googleAuthStub) CompleteGoogleSignIn(ctx context.Context, in *authv1.CompleteGoogleSignInRequest) (*authv1.CompleteGoogleSignInResponse, error) {
	if err := s.record(ctx, "complete"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.completeReq = in
	s.mu.Unlock()
	return &authv1.CompleteGoogleSignInResponse{
		Tokens:   &authv1.TokenResponse{AccessToken: "access-google", RefreshToken: "refresh-google", ExpiresAt: "2026-11-02T11:00:00Z"},
		ReturnTo: "/home",
	}, nil
}

func (s *googleAuthStub) SetUsername(ctx context.Context, in *authv1.SetUsernameRequest) (*authv1.SetUsernameResponse, error) {
	if err := s.record(ctx, "username"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.usernameReq = in
	s.mu.Unlock()
	return &authv1.SetUsernameResponse{Username: "sara.k"}, nil
}

func (s *googleAuthStub) forwarded(call string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	authorization, ok := s.calls[call]
	return authorization, ok
}

func dialGoogleStub(t *testing.T, err error) (*Client, *googleAuthStub) {
	t.Helper()
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	stub := &googleAuthStub{err: err}
	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, stub)
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, dialErr := NewClient(listener.Addr().String())
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, stub
}

// TestGoogleSignInForwardsItsFieldsAndNeverTheBearer proves the two Google calls
// carry their own fields and no bearer token, since they run before a session.
func TestGoogleSignInForwardsItsFieldsAndNeverTheBearer(t *testing.T) {
	client, stub := dialGoogleStub(t, nil)
	ctx := context.Background()

	started, err := client.StartGoogleSignIn(ctx, domain.GoogleSignInStart{RedirectURI: "https://app.example.test/callback", ReturnTo: "/home"})
	if err != nil {
		t.Fatalf("StartGoogleSignIn err = %v", err)
	}
	if started != (domain.GoogleSignInStarted{AuthorizationURL: "https://accounts.example.test/authorize", State: "state-value"}) {
		t.Fatalf("StartGoogleSignIn = %+v", started)
	}
	if stub.startReq.GetRedirectUri() != "https://app.example.test/callback" || stub.startReq.GetReturnTo() != "/home" {
		t.Fatalf("forwarded start = %+v", stub.startReq)
	}
	if authorization, ok := stub.forwarded("start"); !ok || authorization != "" {
		t.Fatalf("start forwarded authorization %q", authorization)
	}

	completed, err := client.CompleteGoogleSignIn(ctx, "state-value", "code-value")
	if err != nil {
		t.Fatalf("CompleteGoogleSignIn err = %v", err)
	}
	want := domain.GoogleSignInCompletion{
		Tokens:   domain.TokenPair{AccessToken: "access-google", RefreshToken: "refresh-google", ExpiresAt: "2026-11-02T11:00:00Z"},
		ReturnTo: "/home",
	}
	if completed != want {
		t.Fatalf("CompleteGoogleSignIn = %+v, want %+v", completed, want)
	}
	if stub.completeReq.GetState() != "state-value" || stub.completeReq.GetCode() != "code-value" {
		t.Fatalf("forwarded complete = %+v", stub.completeReq)
	}
	if authorization, ok := stub.forwarded("complete"); !ok || authorization != "" {
		t.Fatalf("complete forwarded authorization %q", authorization)
	}
}

func TestGoogleSignInFailedPreconditionBecomesNotFound(t *testing.T) {
	client, _ := dialGoogleStub(t, status.Error(codes.FailedPrecondition, "google sign-in is disabled"))

	_, err := client.StartGoogleSignIn(context.Background(), domain.GoogleSignInStart{RedirectURI: "https://app.example.test/callback"})
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindNotFound || failure.Message != "google sign-in is off" {
		t.Fatalf("StartGoogleSignIn err = %v, want KindNotFound google sign-in is off", err)
	}

	_, err = client.CompleteGoogleSignIn(context.Background(), "state-value", "code-value")
	failure, ok = domain.AsError(err)
	if !ok || failure.Kind != domain.KindNotFound || failure.Message != "google sign-in is off" {
		t.Fatalf("CompleteGoogleSignIn err = %v, want KindNotFound google sign-in is off", err)
	}
}

func TestSetUsernameForwardsTheBearerTokenAndReturnsTheStoredForm(t *testing.T) {
	client, stub := dialGoogleStub(t, nil)

	username, err := client.SetUsername(context.Background(), "Sara.K", "access-token")
	if err != nil {
		t.Fatalf("SetUsername err = %v", err)
	}
	if username != "sara.k" {
		t.Fatalf("SetUsername = %q, want the stored form", username)
	}
	if stub.usernameReq.GetUsername() != "Sara.K" {
		t.Fatalf("forwarded username = %q", stub.usernameReq.GetUsername())
	}
	if authorization, _ := stub.forwarded("username"); authorization != "Bearer access-token" {
		t.Fatalf("forwarded authorization = %q", authorization)
	}
}

func TestSetUsernameStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		kind domain.Kind
	}{
		{"taken is a conflict", status.Error(codes.AlreadyExists, "username taken"), domain.KindConflict},
		{"invalid argument", status.Error(codes.InvalidArgument, "username too short"), domain.KindInvalidArgument},
		{"unauthenticated", status.Error(codes.Unauthenticated, "authentication required"), domain.KindUnauthenticated},
		{"permission denied", status.Error(codes.PermissionDenied, "not allowed"), domain.KindPermissionDenied},
		{"internal is generic", status.Error(codes.Internal, "pg: connection reset"), domain.KindBadGateway},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := dialGoogleStub(t, tc.err)
			_, err := client.SetUsername(context.Background(), "sara.k", "access-token")
			failure, ok := domain.AsError(err)
			if !ok || failure.Kind != tc.kind {
				t.Fatalf("SetUsername err = %v, want kind %d", err, tc.kind)
			}
			if tc.kind == domain.KindBadGateway && failure.Message != "upstream error" {
				t.Fatalf("message = %q, want the generic upstream error", failure.Message)
			}
		})
	}
}
