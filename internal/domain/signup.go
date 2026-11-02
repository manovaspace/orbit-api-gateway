package domain

import "context"

// SignupRegistration is one self-serve registration. InviteToken, when valid
// for the same address, joins the inviting organization and skips the OTP.
type SignupRegistration struct {
	Email       string
	Password    string
	DisplayName string
	Locale      string
	OrgName     string
	InviteToken string
}

// SignupVerification consumes a sign-up OTP and the pending password.
type SignupVerification struct {
	Email    string
	Code     string
	Password string
}

// SignupService is the self-serve registration port over orbit-auth's
// SignupService. Both calls are unauthenticated; a disabled sign-up surface is
// reported as a failed precondition and the edge renders it as 404.
type SignupService interface {
	RegisterWithEmail(ctx context.Context, in SignupRegistration) error
	VerifySignup(ctx context.Context, in SignupVerification) (TokenPair, error)
}
