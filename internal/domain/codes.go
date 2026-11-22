package domain

// Stable machine-readable error codes. The edge writes one as the `code` field of
// an error body, next to `error`. Clients branch on the code, never on the text.
// Product sign-in clients read these values exactly; do not rename them.
const (
	CodeInviteNeedsPassword  = "invite_needs_password"
	CodeInviteInvalid        = "invite_invalid"
	CodeSignUpDisabled       = "sign_up_disabled"
	CodeStateExpired         = "state_expired"
	CodeGoogleNotAllowed     = "google_not_allowed"
	CodeGoogleEmailMismatch  = "google_email_mismatch"
	CodeGoogleAlreadyLinked  = "google_already_linked"
	CodeGoogleIdentityTaken  = "google_identity_taken"
	CodeGoogleNotLinked      = "google_not_linked"
	CodeInvalidCredentials   = "invalid_credentials"
	CodeInvalidRefresh       = "invalid_refresh"
	CodePasswordTooShort     = "password_too_short"
	CodePasswordRequired     = "password_required"
	CodeNoPasswordIdentifier = "no_password_identifier"
	CodeLastSignInMethod     = "last_sign_in_method"
)
