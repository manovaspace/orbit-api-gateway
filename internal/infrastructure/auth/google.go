package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// StartGoogleSignIn begins a Google sign-in. Neither Google call carries the
// caller's bearer token: the sign-in happens before any session exists.
func (c *Client) StartGoogleSignIn(ctx context.Context, in domain.GoogleSignInStart) (domain.GoogleSignInStarted, error) {
	resp, err := c.api.StartGoogleSignIn(ctx, &authv1.StartGoogleSignInRequest{
		RedirectUri: in.RedirectURI,
		ReturnTo:    in.ReturnTo,
	})
	if err != nil {
		return domain.GoogleSignInStarted{}, googleUpstreamError(err)
	}
	return domain.GoogleSignInStarted{
		AuthorizationURL: resp.GetAuthorizationUrl(),
		State:            resp.GetState(),
	}, nil
}

// CompleteGoogleSignIn exchanges the state and the authorization code for a token
// pair. It sends no bearer token.
func (c *Client) CompleteGoogleSignIn(ctx context.Context, state, code string) (domain.GoogleSignInCompletion, error) {
	resp, err := c.api.CompleteGoogleSignIn(ctx, &authv1.CompleteGoogleSignInRequest{
		State: state,
		Code:  code,
	})
	if err != nil {
		return domain.GoogleSignInCompletion{}, googleUpstreamError(err)
	}
	return domain.GoogleSignInCompletion{
		Tokens:   tokenPair(resp.GetTokens()),
		ReturnTo: resp.GetReturnTo(),
	}, nil
}

// googleUpstreamError hides a disabled Google sign-in behind a 404, the way a
// disabled sign-up surface is hidden. Every other failure follows orgUpstreamError.
func googleUpstreamError(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition {
		return domain.NewError(domain.KindNotFound, "google sign-in is off")
	}
	return orgUpstreamError(err)
}
