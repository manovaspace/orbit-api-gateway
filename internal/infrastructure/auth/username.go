package auth

import (
	"context"

	authv1 "github.com/manovaspace/orbit-auth/api/auth/v1"
)

// SetUsername sets the caller's username. The bearer token is forwarded the way
// the organization calls forward it, so orbit-auth verifies the caller.
func (c *Client) SetUsername(ctx context.Context, username, accessToken string) (string, error) {
	resp, err := c.api.SetUsername(callerContext(ctx, accessToken), &authv1.SetUsernameRequest{Username: username})
	if err != nil {
		return "", orgUpstreamError(err)
	}
	return resp.GetUsername(), nil
}
