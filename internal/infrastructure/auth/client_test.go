package auth

import (
	"context"
	"errors"
	"net"
	"testing"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// upstreamStub answers every call with one scripted error, or with a fixed
// success value when err is nil.
type upstreamStub struct {
	authv1.UnimplementedAuthServiceServer
	err error
}

func (s upstreamStub) RequestOTP(context.Context, *authv1.RequestOTPRequest) (*authv1.RequestOTPResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.RequestOTPResponse{ExpiresAt: "2026-08-30T23:00:00Z"}, nil
}

func (s upstreamStub) VerifyOTP(context.Context, *authv1.VerifyOTPRequest) (*authv1.VerifyOTPResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.VerifyOTPResponse{Tokens: &authv1.TokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: "e"}}, nil
}

func (s upstreamStub) LoginWithPassword(context.Context, *authv1.LoginWithPasswordRequest) (*authv1.TokenResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.TokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresAt: "e"}, nil
}

func (s upstreamStub) RefreshToken(context.Context, *authv1.RefreshTokenRequest) (*authv1.TokenResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.TokenResponse{AccessToken: "access2", RefreshToken: "refresh2", ExpiresAt: "e"}, nil
}

func (s upstreamStub) RevokeRefreshToken(context.Context, *authv1.RevokeRefreshTokenRequest) (*authv1.RevokeRefreshTokenResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.RevokeRefreshTokenResponse{}, nil
}

func (s upstreamStub) ValidateApiToken(_ context.Context, in *authv1.ValidateApiTokenRequest) (*authv1.ValidateApiTokenResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &authv1.ValidateApiTokenResponse{UserId: "user-" + in.GetSecret(), Scopes: []string{"read"}}, nil
}

func dialStub(t *testing.T, err error) *Client {
	t.Helper()
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, upstreamStub{err: err})
	go func() { _ = gs.Serve(listener) }()
	t.Cleanup(gs.Stop)

	client, dialErr := NewClient(listener.Addr().String())
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestCallsSucceedThroughTheAdapter(t *testing.T) {
	client := dialStub(t, nil)
	ctx := context.Background()

	expiresAt, err := client.RequestOTP(ctx, domain.OTPRequest{Identifier: "person@example.com", Channel: "email"})
	if err != nil || expiresAt != "2026-08-30T23:00:00Z" {
		t.Fatalf("RequestOTP = %q, %v", expiresAt, err)
	}
	if pair, err := client.VerifyOTP(ctx, domain.OTPVerification{Code: "123456"}); err != nil || pair.AccessToken != "access" {
		t.Fatalf("VerifyOTP = %+v, %v", pair, err)
	}
	if pair, err := client.LoginWithPassword(ctx, domain.PasswordLogin{Identifier: "+989121234567", Password: "p"}); err != nil || pair.RefreshToken != "refresh" {
		t.Fatalf("LoginWithPassword = %+v, %v", pair, err)
	}
	if pair, err := client.RefreshToken(ctx, "refresh-token"); err != nil || pair.AccessToken != "access2" {
		t.Fatalf("RefreshToken = %+v, %v", pair, err)
	}
	if err := client.RevokeRefreshToken(ctx, "refresh-token"); err != nil {
		t.Fatalf("RevokeRefreshToken = %v", err)
	}
	identity, err := client.ValidateAPIToken(ctx, "oat_x")
	if err != nil || identity.UserID != "user-oat_x" || len(identity.Scopes) != 1 {
		t.Fatalf("ValidateAPIToken = %+v, %v", identity, err)
	}
}

func TestRevokeRefreshTokenMapsUpstreamFailure(t *testing.T) {
	client := dialStub(t, status.Error(codes.Internal, "pg: connection reset"))
	err := client.RevokeRefreshToken(context.Background(), "refresh-token")
	failure, ok := domain.AsError(err)
	if !ok || failure.Kind != domain.KindInternal || failure.Message != "upstream error" {
		t.Fatalf("RevokeRefreshToken err = %v, want internal upstream error", err)
	}
}

func TestStatusCodesMapToDomainKinds(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		want    domain.Kind
		message string
	}{
		{"invalid argument", status.Error(codes.InvalidArgument, "bad identifier"), domain.KindInvalidArgument, "bad identifier"},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad token"), domain.KindUnauthenticated, "bad token"},
		{"permission denied", status.Error(codes.PermissionDenied, "no"), domain.KindPermissionDenied, "no"},
		{"failed precondition", status.Error(codes.FailedPrecondition, "missing"), domain.KindFailedPrecondition, "missing"},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "slow down"), domain.KindResourceExhausted, "slow down"},
		{"internal hides the upstream detail", status.Error(codes.Internal, "pg: connection reset"), domain.KindInternal, "upstream error"},
		{"not found hides the upstream detail", status.Error(codes.NotFound, "user 42"), domain.KindInternal, "upstream error"},
		{"plain error", errors.New("boom"), domain.KindInternal, "upstream error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := dialStub(t, tc.err)
			_, err := client.RequestOTP(context.Background(), domain.OTPRequest{Identifier: "x"})
			failure, ok := domain.AsError(err)
			if !ok {
				t.Fatalf("err = %v, want a domain error", err)
			}
			if failure.Kind != tc.want {
				t.Fatalf("kind = %v, want %v", failure.Kind, tc.want)
			}
			if failure.Message != tc.message {
				t.Fatalf("message = %q, want %q", failure.Message, tc.message)
			}
		})
	}
}
