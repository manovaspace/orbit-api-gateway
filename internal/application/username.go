package application

import (
	"context"
)

// SetUsername sets the caller's username. The access token is the caller's
// bearer token; orbit-auth takes the account from it.
func (s *Service) SetUsername(ctx context.Context, username, accessToken string) (string, error) {
	return s.usernames.SetUsername(ctx, username, accessToken)
}
