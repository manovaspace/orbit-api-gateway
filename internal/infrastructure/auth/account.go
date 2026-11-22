package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Upstream messages the account mapping names. They are orbit-auth's constant
// domain errors, which the gateway cannot import.
const (
	upstreamInvalidCredentials   = "invalid credentials"
	upstreamInvalidRefresh       = "invalid refresh token"
	upstreamPasswordRequired     = "password is required"
	upstreamPasswordTooShort     = "password must be at least 8 characters"
	upstreamNoPasswordIdentifier = "account needs a verified email, a mobile number or a username to sign in with a password"
	upstreamLastSignInMethod     = "the last sign-in method cannot be removed"
	upstreamGoogleAlreadyLinked  = "google is already linked"
	upstreamGoogleIdentityTaken  = "google account is linked to another user"
	upstreamGoogleNotLinked      = "google is not linked"
	upstreamGoogleOff            = "google sign-in is off"
)

// GetSignInMethods returns how the caller's account signs in.
func (c *Client) GetSignInMethods(ctx context.Context, accessToken string) (domain.SignInMethods, error) {
	resp, err := c.account.GetSignInMethods(callerContext(ctx, accessToken), &authv1.GetSignInMethodsRequest{})
	if err != nil {
		return domain.SignInMethods{}, accountUpstreamError(err)
	}
	methods := domain.SignInMethods{
		HasPassword:    resp.GetHasPassword(),
		Username:       resp.GetUsername(),
		Email:          resp.GetEmail(),
		EmailVerified:  resp.GetEmailVerified(),
		Mobile:         resp.GetMobile(),
		MobileVerified: resp.GetMobileVerified(),
	}
	for _, link := range resp.GetGoogle() {
		methods.Google = append(methods.Google, domain.GoogleLink{
			Email:       link.GetEmail(),
			LinkedAt:    link.GetLinkedAt(),
			LastLoginAt: link.GetLastLoginAt(),
		})
	}
	return methods, nil
}

// SetPassword sets or changes the caller's password.
func (c *Client) SetPassword(ctx context.Context, in domain.SetPasswordRequest, accessToken string) error {
	_, err := c.account.SetPassword(callerContext(ctx, accessToken), &authv1.SetPasswordRequest{
		CurrentPassword: in.CurrentPassword,
		NewPassword:     in.NewPassword,
		RefreshToken:    in.RefreshToken,
	})
	return accountUpstreamError(err)
}

// StartGoogleLink begins linking a Google account to the caller.
func (c *Client) StartGoogleLink(ctx context.Context, in domain.GoogleLinkStart, accessToken string) (domain.GoogleLinkStarted, error) {
	resp, err := c.account.StartGoogleLink(callerContext(ctx, accessToken), &authv1.StartGoogleLinkRequest{
		RedirectUri: in.RedirectURI,
		ReturnTo:    in.ReturnTo,
	})
	if err != nil {
		return domain.GoogleLinkStarted{}, accountUpstreamError(err)
	}
	return domain.GoogleLinkStarted{AuthorizationURL: resp.GetAuthorizationUrl(), State: resp.GetState()}, nil
}

// CompleteGoogleLink finishes a Google link. It issues no tokens.
func (c *Client) CompleteGoogleLink(ctx context.Context, in domain.GoogleLinkComplete, accessToken string) (domain.GoogleLinked, error) {
	resp, err := c.account.CompleteGoogleLink(callerContext(ctx, accessToken), &authv1.CompleteGoogleLinkRequest{
		State: in.State,
		Code:  in.Code,
	})
	if err != nil {
		return domain.GoogleLinked{}, accountUpstreamError(err)
	}
	return domain.GoogleLinked{ReturnTo: resp.GetReturnTo(), Email: resp.GetEmail()}, nil
}

// UnlinkGoogle removes the caller's Google account.
func (c *Client) UnlinkGoogle(ctx context.Context, accessToken string) error {
	_, err := c.account.UnlinkGoogle(callerContext(ctx, accessToken), &authv1.UnlinkGoogleRequest{})
	return accountUpstreamError(err)
}

// RevokeAllSessions revokes the caller's refresh tokens, except refreshToken.
func (c *Client) RevokeAllSessions(ctx context.Context, refreshToken, accessToken string) error {
	_, err := c.account.RevokeAllSessions(callerContext(ctx, accessToken), &authv1.RevokeAllSessionsRequest{RefreshToken: refreshToken})
	return accountUpstreamError(err)
}

// accountUpstreamError maps the account calls. A stable code is set where the
// client branches on the refusal. A Google-only call with Google off answers 404.
// Anything unnamed follows orgUpstreamError.
func accountUpstreamError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return orgUpstreamError(err)
	}
	switch st.Code() {
	case codes.Unauthenticated:
		switch st.Message() {
		case upstreamInvalidCredentials:
			// 403, not 401: a 401 reads as an ended session to the client.
			return domain.NewCodedError(domain.KindPermissionDenied, domain.CodeInvalidCredentials, "the current password is not correct")
		case upstreamInvalidRefresh:
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodeInvalidRefresh, "the refresh token is not valid")
		case upstreamGoogleFailed:
			// The same message covers an unknown state and a failed exchange, so
			// the link completion reports it as an expired attempt, as the Google
			// sign-in completion does.
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodeStateExpired, "the Google sign-in attempt has expired")
		}
	case codes.InvalidArgument:
		switch st.Message() {
		case upstreamPasswordRequired:
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodePasswordRequired, "the password is required")
		case upstreamPasswordTooShort:
			return domain.NewCodedError(domain.KindInvalidArgument, domain.CodePasswordTooShort, "the new password is too short")
		}
	case codes.FailedPrecondition:
		switch st.Message() {
		case upstreamNoPasswordIdentifier:
			return domain.NewCodedError(domain.KindConflict, domain.CodeNoPasswordIdentifier, "add an email address or a phone number before setting a password")
		case upstreamLastSignInMethod:
			return domain.NewCodedError(domain.KindConflict, domain.CodeLastSignInMethod, "add a password or another sign-in method before removing Google")
		case upstreamGoogleAlreadyLinked:
			return domain.NewCodedError(domain.KindConflict, domain.CodeGoogleAlreadyLinked, "this account already has a linked Google account")
		case upstreamGoogleOff:
			return domain.NewError(domain.KindNotFound, "google sign-in is off")
		}
	case codes.AlreadyExists:
		if st.Message() == upstreamGoogleIdentityTaken {
			return domain.NewCodedError(domain.KindConflict, domain.CodeGoogleIdentityTaken, "this Google account is linked to another account")
		}
	case codes.NotFound:
		if st.Message() == upstreamGoogleNotLinked {
			return domain.NewCodedError(domain.KindNotFound, domain.CodeGoogleNotLinked, "Google is not linked to this account")
		}
	}
	return orgUpstreamError(err)
}
