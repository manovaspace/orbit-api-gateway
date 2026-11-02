// Package auth is the gRPC adapter for the upstream orbit-auth service. It maps
// the proto wire types to domain types and the gRPC status codes to domain
// error kinds, so nothing above this package imports the proto or gRPC.
package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Client implements domain.AuthService over gRPC.
type Client struct {
	api  authv1.AuthServiceClient
	conn *grpc.ClientConn
}

// NewClient dials the upstream auth service. The caller closes the client.
func NewClient(addr string, opts ...grpc.DialOption) (*Client, error) {
	base := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	opts = append(base, opts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{api: authv1.NewAuthServiceClient(conn), conn: conn}, nil
}

// RequestOTP asks orbit-auth to send a one-time password.
func (c *Client) RequestOTP(ctx context.Context, in domain.OTPRequest) (string, error) {
	resp, err := c.api.RequestOTP(ctx, &authv1.RequestOTPRequest{
		Identifier:    in.Identifier,
		Channel:       in.Channel,
		Email:         in.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		CorrelationId: in.CorrelationID,
	})
	if err != nil {
		return "", upstreamError(err)
	}
	return resp.GetExpiresAt(), nil
}

// VerifyOTP exchanges a one-time password for a token pair.
func (c *Client) VerifyOTP(ctx context.Context, in domain.OTPVerification) (domain.TokenPair, error) {
	resp, err := c.api.VerifyOTP(ctx, &authv1.VerifyOTPRequest{
		Identifier: in.Identifier,
		Channel:    in.Channel,
		Email:      in.Email, //nolint:staticcheck // SA1019: Email kept for proto wire compatibility
		Code:       in.Code,
	})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp.GetTokens()), nil
}

// LoginWithPassword exchanges a password for a token pair.
func (c *Client) LoginWithPassword(ctx context.Context, in domain.PasswordLogin) (domain.TokenPair, error) {
	resp, err := c.api.LoginWithPassword(ctx, &authv1.LoginWithPasswordRequest{
		Identifier: in.Identifier,
		Password:   in.Password,
	})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp), nil
}

// RefreshToken rotates a refresh token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (domain.TokenPair, error) {
	resp, err := c.api.RefreshToken(ctx, &authv1.RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		return domain.TokenPair{}, upstreamError(err)
	}
	return tokenPair(resp), nil
}

// ValidateAPIToken validates an oat_ API token and returns its identity.
func (c *Client) ValidateAPIToken(ctx context.Context, secret string) (domain.APIIdentity, error) {
	resp, err := c.api.ValidateApiToken(ctx, &authv1.ValidateApiTokenRequest{Secret: secret})
	if err != nil {
		return domain.APIIdentity{}, upstreamError(err)
	}
	return domain.APIIdentity{UserID: resp.GetUserId(), Scopes: resp.GetScopes()}, nil
}

// Close closes the upstream connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func tokenPair(tokens *authv1.TokenResponse) domain.TokenPair {
	return domain.TokenPair{
		AccessToken:  tokens.GetAccessToken(),
		RefreshToken: tokens.GetRefreshToken(),
		ExpiresAt:    tokens.GetExpiresAt(),
	}
}

// upstreamError maps a gRPC failure to the domain kind the edge renders. Every
// code without a mapping keeps the single generic 500 body the edge has always
// returned, so an upstream internal detail never reaches a client verbatim.
func upstreamError(err error) error {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.InvalidArgument:
			return domain.NewError(domain.KindInvalidArgument, st.Message())
		case codes.Unauthenticated:
			return domain.NewError(domain.KindUnauthenticated, st.Message())
		case codes.PermissionDenied:
			return domain.NewError(domain.KindPermissionDenied, st.Message())
		case codes.FailedPrecondition:
			return domain.NewError(domain.KindFailedPrecondition, st.Message())
		case codes.ResourceExhausted:
			return domain.NewError(domain.KindResourceExhausted, st.Message())
		}
	}
	return domain.NewError(domain.KindInternal, "upstream error")
}
