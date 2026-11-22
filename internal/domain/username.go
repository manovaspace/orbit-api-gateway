package domain

import "context"

// UsernameService sets the username of the caller over orbit-auth's AuthService.
// The access token is the caller's bearer token; orbit-auth verifies it and
// takes the account from its subject, never from the request.
type UsernameService interface {
	// SetUsername returns the stored form of the username, which orbit-auth
	// trims and lower-cases.
	SetUsername(ctx context.Context, username, accessToken string) (string, error)
}
