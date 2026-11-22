package domain

import "context"

// SignInMethods is how the caller's account signs in. It never carries a
// password hash, a token or a Google subject.
type SignInMethods struct {
	HasPassword    bool
	Google         []GoogleLink
	Username       string
	Email          string
	EmailVerified  bool
	Mobile         string
	MobileVerified bool
}

// GoogleLink is the linked Google account of the caller, at most one.
type GoogleLink struct {
	Email       string
	LinkedAt    string
	LastLoginAt string
}

// SetPasswordRequest sets or changes the caller's password. CurrentPassword is
// required only when the account already has one. RefreshToken names the
// session to keep and is optional. Passwords are bearer-grade secrets: they are
// forwarded and never logged.
type SetPasswordRequest struct {
	CurrentPassword string
	NewPassword     string
	RefreshToken    string
}

// GoogleLinkStart begins linking a Google account to the caller.
type GoogleLinkStart struct {
	RedirectURI string
	ReturnTo    string
}

// GoogleLinkStarted is the browser redirect and the single-use state of a link.
type GoogleLinkStarted struct {
	AuthorizationURL string
	State            string
}

// GoogleLinkComplete finishes a link with the state and the code Google returned.
type GoogleLinkComplete struct {
	State string
	Code  string
}

// GoogleLinked is the outcome of a completed link.
type GoogleLinked struct {
	ReturnTo string
	Email    string
}

// AccountService is the caller's own sign-in methods over orbit-auth's
// AccountService. Every call carries the caller's bearer access token; orbit-auth
// acts on its subject and never on a name in the request.
type AccountService interface {
	GetSignInMethods(ctx context.Context, accessToken string) (SignInMethods, error)
	SetPassword(ctx context.Context, in SetPasswordRequest, accessToken string) error
	StartGoogleLink(ctx context.Context, in GoogleLinkStart, accessToken string) (GoogleLinkStarted, error)
	CompleteGoogleLink(ctx context.Context, in GoogleLinkComplete, accessToken string) (GoogleLinked, error)
	UnlinkGoogle(ctx context.Context, accessToken string) error
	RevokeAllSessions(ctx context.Context, refreshToken, accessToken string) error
}
