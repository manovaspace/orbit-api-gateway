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
		InviteToken: in.InviteToken,
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
		Tokens:        tokenPair(resp.GetTokens()),
		ReturnTo:      resp.GetReturnTo(),
		InviteID:      resp.GetInviteId(),
		OrgID:         resp.GetOrgId(),
		OrgSlug:       resp.GetOrgSlug(),
		Role:          resp.GetRole(),
		AlreadyMember: resp.GetAlreadyMember(),
	}, nil
}

// Upstream messages the Google sign-in mapping names. They are orbit-auth's
// constant domain errors, which the gateway cannot import.
const (
	upstreamInviteNeedsPassword = "google cannot accept a phone invitation"
	upstreamInviteSignUpOff     = "invite sign-up is disabled"
	upstreamInviteEmailMismatch = "invite email mismatch"
	upstreamInvalidInvite       = "invalid invite"
	upstreamAccountNotAllowed   = "account not allowed"
	upstreamGoogleFailed        = "google sign-in failed"
)

// googleUpstreamError maps the Google sign-in calls. The named refusals carry a
// stable code; a disabled Google sign-in, and any other failed precondition, is a
// 404. Every other failure follows orgUpstreamError.
//
// orbit-auth answers an invalid state and a failed code exchange with the same
// Unauthenticated status and message. Both map to state_expired here, because the
// edge cannot tell them apart; orbit-auth must split them to offer google_failed.
func googleUpstreamError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return orgUpstreamError(err)
	}
	switch st.Code() {
	case codes.FailedPrecondition:
		switch st.Message() {
		case upstreamInviteNeedsPassword:
			return domain.NewCodedError(domain.KindFailedPrecondition, domain.CodeInviteNeedsPassword, "this invitation needs a password sign-in")
		case upstreamInviteSignUpOff:
			return domain.NewCodedError(domain.KindFailedPrecondition, domain.CodeSignUpDisabled, "sign-up is disabled for this invitation")
		case upstreamInviteEmailMismatch:
			return domain.NewCodedError(domain.KindConflict, domain.CodeGoogleEmailMismatch, "the Google account does not match the invitation")
		}
		return domain.NewError(domain.KindNotFound, "google sign-in is off")
	case codes.InvalidArgument:
		if st.Message() == upstreamInvalidInvite {
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodeInviteInvalid, "the invitation is not valid")
		}
	case codes.PermissionDenied:
		if st.Message() == upstreamAccountNotAllowed {
			return domain.NewCodedError(domain.KindPermissionDenied, domain.CodeGoogleNotAllowed, upstreamAccountNotAllowed)
		}
	case codes.Unauthenticated:
		if st.Message() == upstreamGoogleFailed {
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodeStateExpired, "the Google sign-in attempt has expired")
		}
	}
	return orgUpstreamError(err)
}
