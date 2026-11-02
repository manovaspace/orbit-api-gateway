package application

import (
	"context"
	"strings"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// Claim completes (or replays) a workstation onboarding claim. The identity in
// the response is derived, not provisioned in a directory: this route has never
// created a real account and still does not.
func (s *Service) Claim(ctx context.Context, in domain.ClaimInput, idempotencyKey string) (domain.ClaimResult, error) {
	token := strings.TrimSpace(in.InviteToken)
	uid := domain.NormalizeUID(in.DesiredUID)
	if token == "" || uid == "" {
		return domain.ClaimResult{}, domain.NewError(domain.KindInvalidArgument, "invite_token and desired_uid are required")
	}

	key := idempotencyKey
	if key == "" {
		key = token + ":" + uid
	}
	if cached, ok := s.claims.Get(ctx, key); ok {
		cached.IdempotentReplay = true
		s.logger("onboard_claim_replayed", "uid", uid)
		return cached, nil
	}

	email, displayName, groups := domain.ClaimDefaults(uid, in.Email, in.DisplayName)
	result := domain.ClaimResult{
		Status:      domain.ClaimStatusProvisioned,
		User:        domain.ClaimUser{UID: uid, Email: email, DisplayName: displayName, Groups: groups},
		Credentials: domain.ClaimCredentialsFor(token, uid),
		Workspace: domain.ClaimWorkspace{
			GitRemoteBase:        domain.ClaimGitRemoteBase,
			DefaultManifestScope: domain.ClaimDefaultManifestScope,
		},
	}
	s.claims.Put(ctx, key, result)
	s.logger("onboard_claim_provisioned", "uid", uid)
	return result, nil
}
