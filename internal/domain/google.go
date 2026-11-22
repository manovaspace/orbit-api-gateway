package domain

import "context"

// GoogleSignInStart asks orbit-auth to begin a Google sign-in. RedirectURI must
// equal one of the redirect URIs orbit-auth was configured with. ReturnTo is a
// path on the product's origin; empty means "/".
type GoogleSignInStart struct {
	RedirectURI string
	ReturnTo    string
	// InviteToken is an optional email invitation token. It is a bearer secret:
	// it is forwarded and never logged. Empty is a plain sign-in.
	InviteToken string
}

// GoogleSignInStarted is the browser redirect and its single-use state. State is
// a secret-bearing value: it is returned to the caller and never logged.
type GoogleSignInStarted struct {
	AuthorizationURL string
	State            string
}

// GoogleSignInCompletion is the token pair issued for a completed Google sign-in
// and the return path given at start.
type GoogleSignInCompletion struct {
	Tokens   TokenPair
	ReturnTo string
	// The invitation the sign-in accepted; all empty for a plain sign-in.
	InviteID      string
	OrgID         string
	OrgSlug       string
	Role          string
	AlreadyMember bool
}

// GoogleSignInService is the Google sign-in port over orbit-auth's AuthService.
// Both calls run before any sign-in, so neither carries a bearer token. A
// disabled Google sign-in is reported as a failed precondition and the edge
// renders it as 404.
type GoogleSignInService interface {
	StartGoogleSignIn(ctx context.Context, in GoogleSignInStart) (GoogleSignInStarted, error)
	CompleteGoogleSignIn(ctx context.Context, state, code string) (GoogleSignInCompletion, error)
}
